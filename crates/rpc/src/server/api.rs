use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::Context as AnyhowContext;
use miden_node_block_producer::{BlockProducerApi, ensure_transaction_has_fee};
use miden_node_proto::clients::NtxBuilderClient;
use miden_node_proto::domain::block::InvalidBlockRange;
use miden_node_proto::generated::rpc::MempoolStats as ProtoMempoolStats;
use miden_node_proto::generated::rpc::api_server::Api;
use miden_node_proto::generated::{self as proto};
use miden_node_store::state::State;
use miden_node_store::{DatabaseError, GetBlockHeaderError};
use miden_node_tracing::{miden_instrument, warn};
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNoteTagLimit,
    QueryParamNullifierPrefixLimit,
    QueryParamStorageMapKeyTotalLimit,
    QueryParamStorageMapSlotLimit,
};
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::retry::{self, Retryable};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::ProvenTransaction;
use tokio::sync::Semaphore;
use tonic::metadata::MetadataMap;
use tonic::{IntoRequest, Request, Status};

use crate::server::api::subscription::{IpBanList, MAX_REPLICA_SUBSCRIPTIONS};
use crate::server::{NetworkTxAuth, RpcBackend};
use crate::{COMPONENT, LOG_TARGET};

// VALIDATOR FAN-OUT
// ================================================================================================

/// Submits the proven transaction to every validator concurrently.
///
/// Every validator must observe every transaction, since a validator only signs blocks whose
/// transactions it has previously validated. A single failed submission therefore fails the whole
/// call.
pub(crate) async fn submit_tx_to_validators(
    validators: &[miden_node_proto::clients::ValidatorClient],
    request: &proto::transaction::ProvenTransaction,
) -> tonic::Result<()> {
    futures::future::try_join_all(validators.iter().map(|validator| {
        let mut validator = validator.clone();
        let request = request.clone();
        async move { validator.submit_proven_transaction(request).await }
    }))
    .await?;
    Ok(())
}

/// Submits each transaction in the batch to every validator concurrently.
///
/// See [`submit_tx_to_validators`] for why every validator must receive the submission.
pub(crate) async fn submit_batch_to_validators(
    validators: &[miden_node_proto::clients::ValidatorClient],
    proposed_batch: &miden_protocol::batch::ProposedBatch,
    sealed_transaction_inputs: &[proto::transaction::SealedTransactionInputs],
) -> tonic::Result<()> {
    futures::future::try_join_all(validators.iter().map(|validator| {
        let mut validator = validator.clone();
        async move { validator.submit_batch(proposed_batch, sealed_transaction_inputs).await }
    }))
    .await?;
    Ok(())
}

/// Rejects a submission if a transaction does not create a canonical fee note.
pub(crate) fn ensure_transactions_have_fee_notes<'a>(
    transactions: impl IntoIterator<Item = &'a ProvenTransaction>,
) -> tonic::Result<()> {
    transactions
        .into_iter()
        .try_for_each(|tx| ensure_transaction_has_fee(tx).map_err(Status::from))
}

// API METHODS
// ================================================================================================

mod get_account;
mod get_block_by_number;
mod get_block_header_by_number;
mod get_limits;
mod get_network_note_status;
mod get_note_script_by_root;
mod get_notes_by_id;
mod get_transaction_encryption_key;
mod status;
mod submit_auth_tx;
mod submit_auth_tx_batch;
mod submit_proven_tx;
mod submit_proven_tx_batch;
mod subscription;
mod sync_account_storage_maps;
mod sync_account_vault;
mod sync_chain_mmr;
mod sync_notes;
mod sync_nullifiers;
mod sync_transactions;

// ================================================================================================

const NETWORK_TX_AUTH_HEADER_NAME: &str = "x-miden-network-tx-auth";

struct RpcInvalidBlockRange(InvalidBlockRange);

impl From<InvalidBlockRange> for RpcInvalidBlockRange {
    fn from(value: InvalidBlockRange) -> Self {
        Self(value)
    }
}

// RPC SERVICE
// ================================================================================================

pub struct RpcService {
    state: Arc<State>,
    backend: RpcBackend,
    ntx_builder: Option<NtxBuilderClient>,
    network_tx_auth: Option<NetworkTxAuth>,
    genesis_commitment: Option<Word>,
    block_header_cache: LruCache<BlockNumber, BlockHeader>,
    block_subscription_semaphore: Arc<Semaphore>,
    proof_subscription_semaphore: Arc<Semaphore>,
    subscription_ban: Arc<IpBanList>,
}

impl RpcService {
    pub(crate) fn new(
        state: Arc<State>,
        backend: RpcBackend,
        ntx_builder: Option<NtxBuilderClient>,
        commitment_cache_capacity: NonZeroUsize,
        network_tx_auth: Option<NetworkTxAuth>,
    ) -> Self {
        Self {
            state,
            backend,
            ntx_builder,
            network_tx_auth,
            genesis_commitment: None,
            block_header_cache: LruCache::new(commitment_cache_capacity),
            block_subscription_semaphore: Arc::new(Semaphore::new(MAX_REPLICA_SUBSCRIPTIONS)),
            proof_subscription_semaphore: Arc::new(Semaphore::new(MAX_REPLICA_SUBSCRIPTIONS)),
            subscription_ban: Arc::new(IpBanList::default()),
        }
    }

    /// Sets the genesis commitment, returning an error if it is already set.
    ///
    /// Required since the genesis header is fetched through the store state after `RpcService`
    /// construction.
    pub fn set_genesis_commitment(&mut self, commitment: Word) -> anyhow::Result<()> {
        if self.genesis_commitment.is_some() {
            return Err(anyhow::anyhow!("genesis commitment already set"));
        }
        self.genesis_commitment = Some(commitment);
        Ok(())
    }

    /// Fetches the genesis block header from the store.
    ///
    /// Automatically retries until the store connection becomes available.
    pub async fn get_genesis_header_with_retry(&self) -> anyhow::Result<BlockHeader> {
        // Retry with exponential backoff (base 500ms, max 30s) while the store is unavailable.
        let header = (|| async {
            self.get_block_header_by_number(
                proto::rpc::BlockHeaderByNumberRequest {
                    block_num: Some(BlockNumber::GENESIS.as_u32()),
                    include_mmr_proof: None,
                }
                .into_request(),
            )
            .await
        })
        .retry(retry::exponential(Duration::from_millis(500), Duration::from_secs(30)))
        .when(|err| err.code() == tonic::Code::Unavailable)
        .notify(|err, backoff| {
            warn!(
                err,
                target: LOG_TARGET,
                "connection failed while fetching genesis header, retrying",
                retry.delay_ms = backoff.as_millis() as u64
            );
        })
        .await?;

        let header = header.into_inner().block_header.context("response is missing the header")?;
        BlockHeader::try_from(header).context("failed to parse response")
    }

    /// Returns the given block's onchain header.
    ///
    /// This is retrieved from the local LRU cache, or otherwise from the store on cache miss.
    #[miden_instrument(
        target = COMPONENT,
        name = "get_block_header",
        fields(
            block.number = block,
        ),
    )]
    async fn get_block_header(&self, block: BlockNumber) -> Result<BlockHeader, Status> {
        if let Some(header) = self.block_header_cache.get(&block) {
            return Ok(header);
        }

        let header = self
            .state
            .view()
            .get_block_header(Some(block), false)
            .await
            .map_err(get_block_header_error_to_status)?
            .0
            .ok_or_else(|| Status::invalid_argument(format!("unknown block {block}")))?;

        self.block_header_cache.put(block, header.clone());

        Ok(header)
    }

    /// Returns the reference block header, or an error if its commitment is not on chain.
    async fn verify_reference_commitment(
        &self,
        block: BlockNumber,
        commitment: Word,
    ) -> Result<BlockHeader, Status> {
        let header = self.get_block_header(block).await?;
        let onchain = header.commitment();

        if onchain != commitment {
            return Err(Status::invalid_argument(format!(
                "reference block's commitment {commitment} at block {block} does not match the chain's commitment of {onchain}",
            )));
        }

        Ok(header)
    }

    /// Errors if any of `candidate_ids` is classified as a network account by the store. Callers
    /// should pre-filter to post-deployment, public-account ids; `Ok(())` on empty.
    async fn reject_if_any_network_accounts(
        &self,
        candidate_ids: impl IntoIterator<Item = AccountId>,
    ) -> Result<(), Status> {
        let account_ids: Vec<AccountId> = candidate_ids.into_iter().collect();
        if account_ids.is_empty() {
            return Ok(());
        }

        let network_accounts =
            self.state.view().filter_network_accounts(&account_ids).await.map_err(|err| {
                Status::internal(format!("network-account classification failed: {err}"))
            })?;

        if !network_accounts.is_empty() {
            return Err(Status::invalid_argument(
                "Network transactions may not be submitted by users yet",
            ));
        }

        Ok(())
    }

    fn is_authorized_network_tx(&self, metadata: &MetadataMap) -> bool {
        let Some(auth) = &self.network_tx_auth else {
            return false;
        };

        metadata.get(NETWORK_TX_AUTH_HEADER_NAME).is_some_and(|value| value == auth.0)
    }
}

// INTERNAL SEQUENCER SERVICE
// ================================================================================================

pub(crate) struct SequencerInternalService {
    pub(crate) state: Arc<State>,
    pub(crate) block_producer: BlockProducerApi,
}

// HELPERS
// ================================================================================================

fn get_block_header_error_to_status(err: GetBlockHeaderError) -> Status {
    match err {
        GetBlockHeaderError::DatabaseError(err) => database_error_to_status(&err),
        GetBlockHeaderError::MmrError(err) => Status::internal(err.to_string()),
    }
}

fn database_error_to_status(err: &DatabaseError) -> Status {
    let message = err.to_string();
    match err {
        DatabaseError::AccountNotFoundInDb(_)
        | DatabaseError::AccountsNotFoundInDb(_)
        | DatabaseError::AccountNotPublic(_) => Status::not_found(message),
        DatabaseError::TransactionPageExceedsPayloadLimit { .. } => Status::out_of_range(message),
        DatabaseError::RangeBeyondTip(_) => Status::invalid_argument(message),
        _ => Status::internal(message),
    }
}

fn invalid_block_range_to_status(RpcInvalidBlockRange(err): RpcInvalidBlockRange) -> Status {
    Status::invalid_argument(err.to_string())
}

// LIMIT HELPERS
// ================================================================================================

/// Formats an "Out of range" error
fn out_of_range_error<E: core::fmt::Display>(err: E) -> Status {
    Status::out_of_range(err.to_string())
}

/// Check, but don't repeat ourselves mapping the error
fn check<Q: QueryParamLimiter>(n: usize) -> Result<(), Status> {
    <Q as QueryParamLimiter>::check(n).map_err(out_of_range_error)
}

/// Helper to build an [`EndpointLimits`](proto::rpc::EndpointLimits) from (name, limit) pairs.
fn endpoint_limits(params: &[(&str, usize)]) -> proto::rpc::EndpointLimits {
    proto::rpc::EndpointLimits {
        parameters: params.iter().map(|(k, v)| ((*k).to_string(), *v as u32)).collect(),
    }
}

/// Cached RPC query parameter limits.
static RPC_LIMITS: LazyLock<proto::rpc::RpcLimits> = LazyLock::new(|| {
    use QueryParamAccountIdLimit as AccountId;
    use QueryParamNoteIdLimit as NoteId;
    use QueryParamNoteTagLimit as NoteTag;
    use QueryParamNullifierPrefixLimit as NullifierPrefix;
    use QueryParamStorageMapKeyTotalLimit as StorageMapKeyTotal;
    use QueryParamStorageMapSlotLimit as StorageMapSlot;

    proto::rpc::RpcLimits {
        endpoints: std::collections::HashMap::from([
            (
                "SyncNullifiers".into(),
                endpoint_limits(&[(NullifierPrefix::PARAM_NAME, NullifierPrefix::LIMIT)]),
            ),
            (
                "SyncTransactions".into(),
                endpoint_limits(&[(AccountId::PARAM_NAME, AccountId::LIMIT)]),
            ),
            ("SyncNotes".into(), endpoint_limits(&[(NoteTag::PARAM_NAME, NoteTag::LIMIT)])),
            ("GetNotesById".into(), endpoint_limits(&[(NoteId::PARAM_NAME, NoteId::LIMIT)])),
            (
                "GetAccount".into(),
                endpoint_limits(&[
                    (StorageMapKeyTotal::PARAM_NAME, StorageMapKeyTotal::LIMIT),
                    (StorageMapSlot::PARAM_NAME, StorageMapSlot::LIMIT),
                ]),
            ),
        ]),
    }
});

#[cfg(test)]
mod tests {
    use miden_node_proto::generated::server::rpc_api::GetLimits;

    use super::*;

    #[test]
    fn get_limits_decodes_unit_request() {
        assert_eq!(RpcService::decode(()).unwrap(), ());
    }
}
