use std::num::NonZeroUsize;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Context as AnyhowContext;
use http::header::ACCEPT;
use miden_node_block_producer::{BlockProducerStatus, MempoolStats as BlockProducerMempoolStats};
use miden_node_proto::clients::NtxBuilderClient;
use miden_node_proto::decode::{
    convert_digests_to_words,
    read_account_id,
    read_account_ids,
    read_block_range,
    read_root,
};
use miden_node_proto::domain::account::{AccountRequest, AccountStorageRequest, SlotData};
use miden_node_proto::domain::block::InvalidBlockRange;
use miden_node_proto::generated::rpc::MempoolStats as ProtoMempoolStats;
use miden_node_proto::generated::rpc::api_server::{self, Api};
use miden_node_proto::generated::{self as proto};
use miden_node_store::state::{Finality, State, StateSubscriptionError};
use miden_node_store::{
    DatabaseError,
    GetAccountError,
    GetBlockHeaderError,
    NoteRecord,
    NoteSyncError,
    NoteSyncRecord,
    TransactionRecord,
};
use miden_node_utils::ErrorReport;
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNoteTagLimit,
    QueryParamNullifierPrefixLimit,
    QueryParamStorageMapKeyTotalLimit,
};
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::retry::{self, Retryable};
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::NoteId;
use miden_protocol::transaction::{
    OutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TxAccountUpdate,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, Word};
use miden_tx::TransactionVerifier;
use miden_tx_batch_prover::LocalBatchProver;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_stream::{Stream, StreamExt};
use tonic::metadata::MetadataMap;
use tonic::{IntoRequest, Request, Response, Status};
use tracing::{Span, debug, info_span};

use crate::COMPONENT;
use crate::server::{NetworkTxAuth, RpcMode};

const NETWORK_TX_AUTH_HEADER_NAME: &str = "x-miden-network-tx-auth";

/// Maximum number of concurrent block or proof subscriptions served by this RPC instance.
const MAX_REPLICA_SUBSCRIPTIONS: usize = 10;

type BlockSubscriptionStream = Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::BlockSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;

type ProofSubscriptionStream = Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::ProofSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;

struct GuardedStream<S> {
    inner: S,
    _permit: OwnedSemaphorePermit,
}

impl<S> GuardedStream<S> {
    fn new(inner: S, permit: OwnedSemaphorePermit) -> Self {
        Self { inner, _permit: permit }
    }
}

impl<S> Stream for GuardedStream<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

struct RpcInvalidBlockRange(InvalidBlockRange);

impl From<InvalidBlockRange> for RpcInvalidBlockRange {
    fn from(value: InvalidBlockRange) -> Self {
        Self(value)
    }
}

// RPC SERVICE
// ================================================================================================

pub struct RpcService {
    store: Arc<State>,
    mode: RpcMode,
    ntx_builder: Option<NtxBuilderClient>,
    network_tx_auth: Option<NetworkTxAuth>,
    genesis_commitment: Option<Word>,
    block_commitment_cache: LruCache<BlockNumber, Word>,
    block_subscription_semaphore: Arc<Semaphore>,
    proof_subscription_semaphore: Arc<Semaphore>,
}

impl RpcService {
    pub(crate) fn new(
        store: Arc<State>,
        mode: RpcMode,
        ntx_builder: Option<NtxBuilderClient>,
        commitment_cache_capacity: NonZeroUsize,
        network_tx_auth: Option<NetworkTxAuth>,
    ) -> Self {
        Self {
            store,
            mode,
            ntx_builder,
            network_tx_auth,
            genesis_commitment: None,
            block_commitment_cache: LruCache::new(commitment_cache_capacity),
            block_subscription_semaphore: Arc::new(Semaphore::new(MAX_REPLICA_SUBSCRIPTIONS)),
            proof_subscription_semaphore: Arc::new(Semaphore::new(MAX_REPLICA_SUBSCRIPTIONS)),
        }
    }

    /// Sets the genesis commitment, returning an error if it is already set.
    ///
    /// Required since the store client is used to fetch the `genesis_commitment` after
    /// `RpcService` construction.
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
            tracing::warn!(
                ?backoff,
                %err,
                "connection failed while fetching genesis header, retrying"
            );
        })
        .await?;

        let header = header.into_inner().block_header.context("response is missing the header")?;
        BlockHeader::try_from(header).context("failed to parse response")
    }

    /// Returns the given block's onchain commitment.
    ///
    /// This is retrieved from the local LRU cache, or otherwise from the store on cache miss.
    #[tracing::instrument(target = COMPONENT, name = "get_block_commitment", skip_all, fields(block.number = %block))]
    async fn get_block_commitment(&self, block: BlockNumber) -> Result<Word, Status> {
        if let Some(commitment) = self.block_commitment_cache.get(&block) {
            return Ok(commitment);
        }

        let header = self
            .store
            .get_block_header(Some(block), false)
            .await
            .map_err(get_block_header_error_to_status)?
            .0
            .ok_or_else(|| Status::invalid_argument(format!("unknown block {block}")))?;

        let commitment = header.commitment();
        self.block_commitment_cache.put(block, commitment);

        Ok(commitment)
    }

    /// Returns an error if the provided block's commitment does not match the one on chain.
    async fn verify_reference_commitment(
        &self,
        block: BlockNumber,
        commitment: Word,
    ) -> Result<(), Status> {
        let onchain = self.get_block_commitment(block).await?;

        if onchain != commitment {
            return Err(Status::invalid_argument(format!(
                "reference block's commitment {commitment} at block {block} does not match the chain's commitment of {onchain}",
            )));
        }

        Ok(())
    }

    /// Fetches the committed chain tip and ensures the requested range does not extend beyond it.
    ///
    /// Returns the chain tip so callers can reuse it (e.g. in the response's pagination info)
    /// without issuing a second query.
    async fn range_bounds_check(
        &self,
        range: &RangeInclusive<BlockNumber>,
    ) -> Result<BlockNumber, Status> {
        let chain_tip = self.store.chain_tip(Finality::Committed).await;
        if *range.end() > chain_tip {
            return Err(Status::invalid_argument(format!(
                "block_to ({}) is greater than chain tip ({chain_tip})",
                range.end()
            )));
        }

        Ok(chain_tip)
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
            self.store.filter_network_accounts(&account_ids).await.map_err(|err| {
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

// API IMPLEMENTATION
// ================================================================================================

#[tonic::async_trait]
impl api_server::Api for RpcService {
    type BlockSubscriptionStream = BlockSubscriptionStream;
    type ProofSubscriptionStream = ProofSubscriptionStream;

    // -- Nullifier endpoints -----------------------------------------------------------------

    async fn sync_nullifiers(
        &self,
        request: Request<proto::rpc::SyncNullifiersRequest>,
    ) -> Result<Response<proto::rpc::SyncNullifiersResponse>, Status> {
        let range =
            read_block_range::<Status>(request.get_ref().block_range, "SyncNullifiersRequest")?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);

        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNullifierPrefixLimit>(request.get_ref().nullifiers.len())?;

        let request = request.into_inner();
        if request.prefix_len != 16 {
            return Err(Status::invalid_argument(format!(
                "unsupported prefix length: {} (only 16-bit prefixes are supported)",
                request.prefix_len
            )));
        }
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;

        let (nullifiers, block_num) = self
            .store
            .sync_nullifiers(request.prefix_len, request.nullifiers, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let nullifiers = nullifiers
            .into_iter()
            .map(|nullifier_info| proto::rpc::sync_nullifiers_response::NullifierUpdate {
                nullifier: Some(nullifier_info.nullifier.into()),
                block_num: nullifier_info.block_num.as_u32(),
            })
            .collect();

        Ok(Response::new(proto::rpc::SyncNullifiersResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: block_num.as_u32(),
            }),
            nullifiers,
        }))
    }

    // -- Block endpoints ---------------------------------------------------------------------

    async fn get_block_header_by_number(
        &self,
        request: Request<proto::rpc::BlockHeaderByNumberRequest>,
    ) -> Result<Response<proto::rpc::BlockHeaderByNumberResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        Span::current().set_attribute("block.number", request.get_ref().block_num());

        let request = request.into_inner();
        let block_num = request.block_num.map(BlockNumber::from);
        let (block_header, mmr_proof) = self
            .store
            .get_block_header(block_num, request.include_mmr_proof.unwrap_or(false))
            .await
            .map_err(get_block_header_error_to_status)?;

        Ok(Response::new(proto::rpc::BlockHeaderByNumberResponse {
            block_header: block_header.map(Into::into),
            chain_length: mmr_proof.as_ref().map(|p| p.forest().num_leaves() as u32),
            mmr_path: mmr_proof.map(|p| Into::into(p.merkle_path())),
        }))
    }

    async fn get_block_by_number(
        &self,
        request: Request<proto::blockchain::BlockRequest>,
    ) -> Result<Response<proto::blockchain::MaybeBlock>, Status> {
        Span::current().set_attribute("block.number", request.get_ref().block_num);

        let request = request.into_inner();

        debug!(target: COMPONENT, ?request);

        let block_num = BlockNumber::from(request.block_num);
        let block = self
            .store
            .load_block(block_num)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let proof = if request.include_proof.unwrap_or_default() {
            self.store
                .load_proof(block_num)
                .await
                .map_err(|err| database_error_to_status(&err))?
        } else {
            None
        };

        Ok(Response::new(proto::blockchain::MaybeBlock { block, proof }))
    }

    async fn sync_chain_mmr(
        &self,
        request: Request<proto::rpc::SyncChainMmrRequest>,
    ) -> Result<Response<proto::rpc::SyncChainMmrResponse>, Status> {
        let request_ref = request.get_ref();

        let span = Span::current();
        span.set_attribute("current_client_block_height", request_ref.current_client_block_height);
        span.set_attribute("finality_level", request_ref.finality_level().as_str_name());

        debug!(target: COMPONENT, request = ?request_ref);

        let request = request.into_inner();
        let current_client_block_height = BlockNumber::from(request.current_client_block_height);
        let sync_target = match request.finality_level() {
            proto::rpc::FinalityLevel::Committed | proto::rpc::FinalityLevel::Unspecified => {
                self.store.chain_tip(Finality::Committed).await
            },
            proto::rpc::FinalityLevel::Proven => self.store.chain_tip(Finality::Proven).await,
        };

        if current_client_block_height > sync_target {
            return Err(Status::invalid_argument(format!(
                "start block is not known: current client block height {current_client_block_height} is greater than chain tip {sync_target}"
            )));
        }

        let block_range = current_client_block_height..=sync_target;
        let (mmr_delta, block_header, block_signature) = self
            .store
            .sync_chain_mmr(block_range.clone())
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(proto::rpc::SyncChainMmrResponse {
            block_range: Some(proto::rpc::BlockRange {
                block_from: block_range.start().as_u32(),
                block_to: block_range.end().as_u32(),
            }),
            mmr_delta: Some(mmr_delta.into()),
            block_header: Some(block_header.into()),
            block_signature: Some(block_signature.into()),
        }))
    }

    async fn block_subscription(
        &self,
        request: Request<proto::rpc::BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        let request_ref = request.get_ref();
        Span::current().set_attribute("block.from", request_ref.block_from);

        debug!(target: COMPONENT, request = ?request_ref);

        let permit = Arc::clone(&self.block_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum block subscriptions reached"))?;

        let from = BlockNumber::from(request_ref.block_from);
        let stream = self.store.block_subscription(from).map(|event| {
            event
                .map(|event| proto::rpc::BlockSubscriptionResponse {
                    block: event.block,
                    committed_chain_tip: event.committed_chain_tip.as_u32(),
                })
                .map_err(state_subscription_error_to_status)
        });
        let stream: Self::BlockSubscriptionStream =
            Box::pin(GuardedStream::new(Box::pin(stream), permit));
        Ok(Response::new(stream))
    }

    async fn proof_subscription(
        &self,
        request: Request<proto::rpc::ProofSubscriptionRequest>,
    ) -> Result<Response<Self::ProofSubscriptionStream>, Status> {
        let request_ref = request.get_ref();
        Span::current().set_attribute("block.from", request_ref.block_from);

        debug!(target: COMPONENT, request = ?request_ref);

        let permit = Arc::clone(&self.proof_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum proof subscriptions reached"))?;

        let from = BlockNumber::from(request_ref.block_from);
        let stream = self.store.proof_subscription(from).map(|event| {
            event
                .map(|event| proto::rpc::ProofSubscriptionResponse {
                    block_num: event.block_num.as_u32(),
                    proof: event.proof,
                    proven_chain_tip: event.proven_chain_tip.as_u32(),
                })
                .map_err(state_subscription_error_to_status)
        });
        let stream: Self::ProofSubscriptionStream =
            Box::pin(GuardedStream::new(Box::pin(stream), permit));
        Ok(Response::new(stream))
    }

    // -- Note endpoints ----------------------------------------------------------------------

    async fn sync_notes(
        &self,
        request: Request<proto::rpc::SyncNotesRequest>,
    ) -> Result<Response<proto::rpc::SyncNotesResponse>, Status> {
        let range = read_block_range::<Status>(request.get_ref().block_range, "SyncNotesRequest")?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);
        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNoteTagLimit>(request.get_ref().note_tags.len())?;

        let request = request.into_inner();
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;

        let (results, last_block_checked) = self
            .store
            .sync_notes(request.note_tags, block_range)
            .await
            .map_err(note_sync_error_to_status)?;
        let blocks = results
            .into_iter()
            .map(|(state, mmr_proof)| proto::rpc::sync_notes_response::NoteSyncBlock {
                block_header: Some(state.block_header.into()),
                mmr_path: Some(mmr_proof.merkle_path().clone().into()),
                notes: state.notes.into_iter().map(note_sync_record_to_proto).collect(),
            })
            .collect();

        Ok(Response::new(proto::rpc::SyncNotesResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_checked.as_u32(),
            }),
            blocks,
        }))
    }

    async fn get_notes_by_id(
        &self,
        request: Request<proto::note::NoteIdList>,
    ) -> Result<Response<proto::note::CommittedNoteList>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNoteIdLimit>(request.get_ref().ids.len())?;

        let note_ids: Vec<Word> = convert_digests_to_words::<Status, _>(request.into_inner().ids)?;
        let note_ids: Vec<NoteId> = note_ids.into_iter().map(NoteId::from_raw).collect();
        let notes = self
            .store
            .get_notes_by_id(note_ids)
            .await
            .map_err(|err| database_error_to_status(&err))?
            .into_iter()
            .map(note_record_to_proto)
            .collect();

        Ok(Response::new(proto::note::CommittedNoteList { notes }))
    }

    async fn get_note_script_by_root(
        &self,
        request: Request<proto::note::NoteScriptRoot>,
    ) -> Result<Response<proto::rpc::MaybeNoteScript>, Status> {
        let request = request.into_inner();
        debug!(target: COMPONENT, ?request);

        let root = read_root::<Status>(request.root, "NoteScriptRoot")?;
        let script = self
            .store
            .get_note_script_by_root(root)
            .await
            .map_err(|err| database_error_to_status(&err))?;

        Ok(Response::new(proto::rpc::MaybeNoteScript { script: script.map(Into::into) }))
    }

    // -- Account endpoints -------------------------------------------------------------------

    async fn sync_account_storage_maps(
        &self,
        request: Request<proto::rpc::SyncAccountStorageMapsRequest>,
    ) -> Result<Response<proto::rpc::SyncAccountStorageMapsResponse>, Status> {
        let account_id = read_account_id::<proto::rpc::SyncAccountStorageMapsRequest, Status>(
            request.get_ref().account_id.clone(),
        )?;
        let range = read_block_range::<Status>(
            request.get_ref().block_range,
            "SyncAccountStorageMapsRequest",
        )?;

        let span = Span::current();
        span.set_attribute("account.id", account_id);
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);

        debug!(target: COMPONENT, request = ?request.get_ref());

        if !account_id.is_public() {
            return Err(Status::invalid_argument(format!("account {account_id} is not public")));
        }
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;
        let storage_maps_page = self
            .store
            .sync_account_storage_maps(account_id, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let updates = storage_maps_page
            .values
            .into_iter()
            .map(|map_value| proto::rpc::StorageMapUpdate {
                slot_name: map_value.slot_name.to_string(),
                key: Some(map_value.key.into()),
                value: Some(map_value.value.into()),
                block_num: map_value.block_num.as_u32(),
            })
            .collect();

        Ok(Response::new(proto::rpc::SyncAccountStorageMapsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: storage_maps_page.last_block_included.as_u32(),
            }),
            updates,
        }))
    }

    async fn sync_account_vault(
        &self,
        request: tonic::Request<proto::rpc::SyncAccountVaultRequest>,
    ) -> std::result::Result<tonic::Response<proto::rpc::SyncAccountVaultResponse>, tonic::Status>
    {
        let account_id = read_account_id::<proto::rpc::SyncAccountVaultRequest, Status>(
            request.get_ref().account_id.clone(),
        )?;
        let range =
            read_block_range::<Status>(request.get_ref().block_range, "SyncAccountVaultRequest")?;

        let span = Span::current();
        span.set_attribute("account.id", account_id);
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);

        debug!(target: COMPONENT, request = ?request.get_ref());

        if !account_id.is_public() {
            return Err(Status::invalid_argument(format!("account {account_id} is not public")));
        }
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;
        let (last_included_block, updates) = self
            .store
            .sync_account_vault(account_id, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let updates = updates
            .into_iter()
            .map(|update| {
                let vault_key: Word = update.vault_key.into();
                proto::rpc::AccountVaultUpdate {
                    vault_key: Some(vault_key.into()),
                    asset: update.asset.map(Into::into),
                    block_num: update.block_num.as_u32(),
                }
            })
            .collect();

        Ok(Response::new(proto::rpc::SyncAccountVaultResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_included_block.as_u32(),
            }),
            updates,
        }))
    }

    /// Validates storage map key limits before forwarding the account request to the store.
    async fn get_account(
        &self,
        raw_request: Request<proto::rpc::AccountRequest>,
    ) -> Result<Response<proto::rpc::AccountResponse>, Status> {
        let raw_request = raw_request.into_inner();
        debug!(target: COMPONENT, ?raw_request);

        let request = AccountRequest::try_from(raw_request.clone())?;

        let span = Span::current();
        span.set_attribute("account.id", request.account_id);
        if let Some(block) = request.block_num {
            span.set_attribute("block.number", block);
        }

        // Validate total storage map key limit before forwarding to store
        if let Some(details) = &request.details {
            let _span = info_span!(target: COMPONENT, "validate_storage_map_keys").entered();
            let total_keys: usize = match &details.storage_request {
                AccountStorageRequest::None | AccountStorageRequest::AllStorageMaps => 0,
                AccountStorageRequest::Explicit(requests) => requests
                    .iter()
                    .filter_map(|request| match &request.slot_data {
                        SlotData::All => None,
                        SlotData::MapKeys(items) => Some(items.len()),
                    })
                    .sum(),
            };
            check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;
        }

        let account_data =
            self.store.get_account(request).await.map_err(get_account_error_to_status)?;
        Ok(Response::new(account_data.into()))
    }

    // -- Transaction submission --------------------------------------------------------------

    /// Deserializes and rebuilds the transaction with MAST decorators stripped from output note
    /// scripts, verifies the transaction proof, optionally re-executes via the validator if
    /// transaction inputs are provided, then forwards the transaction to the block producer.
    async fn submit_proven_tx(
        &self,
        request: Request<proto::transaction::ProvenTransaction>,
    ) -> Result<Response<proto::blockchain::BlockNumber>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        let is_authorized_network_tx = self.is_authorized_network_tx(request.metadata());
        let original_accept = request.metadata().get(ACCEPT.as_str()).cloned();

        let request = request.into_inner();

        let tx = ProvenTransaction::read_from_bytes(&request.transaction).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid transaction"))
        })?;

        let span = Span::current();
        span.set_attribute("transaction.id", tx.id());
        span.set_attribute("account.id", tx.account_id());
        span.set_attribute("transaction.expires_at", tx.expiration_block_num());
        span.set_attribute("transaction.reference_block.number", tx.ref_block_num());
        span.set_attribute("transaction.reference_block.commitment", tx.ref_block_commitment());

        // Verify the reference block is actually part of the chain.
        self.verify_reference_commitment(tx.ref_block_num(), tx.ref_block_commitment())
            .await?;

        // Rebuild a new ProvenTransaction with decorators removed from output notes
        let account_update = TxAccountUpdate::new(
            tx.account_id(),
            tx.account_update().initial_state_commitment(),
            tx.account_update().final_state_commitment(),
            tx.account_update().account_delta_commitment(),
            tx.account_update().details().clone(),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let stripped_outputs = strip_output_note_decorators(tx.output_notes().iter());
        let rebuilt_tx = ProvenTransaction::new(
            account_update,
            tx.input_notes().iter().cloned(),
            stripped_outputs,
            tx.ref_block_num(),
            tx.ref_block_commitment(),
            tx.fee(),
            tx.expiration_block_num(),
            tx.proof().clone(),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut request = request;
        request.transaction = rebuilt_tx.to_bytes();

        // Block post-deployment network-account transactions from user RPC. First-deployment txs
        // are exempt because the protocol-level allowlist only kicks in once the account exists,
        // and network accounts must be public, so private-account txs are filtered out up front.
        //
        // Skip this check if the client is authorized to send network transactions (ntx-builder).
        if !is_authorized_network_tx {
            let candidate_id = (!tx.account_update().initial_state_commitment().is_empty()
                && tx.account_id().is_public())
            .then(|| tx.account_id());
            self.reject_if_any_network_accounts(candidate_id).await?;
        }

        let tx_id = tx.id();
        spawn_blocking_in_current_span(move || {
            TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&tx).map_err(|err| {
                Status::invalid_argument(format!(
                    "Invalid proof for transaction {}: {}",
                    tx_id,
                    err.as_report()
                ))
            })
        })
        .await
        .map_err(|err| {
            Status::internal(format!("transaction proof verification task failed: {err}"))
        })??;

        // In full node mode we forward the request to the source.
        let (block_producer, validator) = match &self.mode {
            RpcMode::Sequencer { block_producer, validator } => {
                (block_producer.as_ref(), validator.as_ref())
            },
            RpcMode::FullNode { source_rpc, .. } => {
                let mut forwarded_request = Request::new(request);
                if let Some(accept) = original_accept {
                    forwarded_request.metadata_mut().insert(ACCEPT.as_str(), accept);
                }
                return source_rpc.as_ref().clone().submit_proven_tx(forwarded_request).await;
            },
        };

        // Transaction inputs must be provided in order to allow for transaction re-execution via
        // the Validator.
        if request.transaction_inputs.is_some() {
            validator.clone().submit_proven_transaction(request.clone()).await?;
        } else {
            return Err(Status::invalid_argument("Transaction inputs must be provided"));
        }

        block_producer
            .submit_proven_tx(rebuilt_tx)
            .await
            .map(Into::into)
            .map(Response::new)
            .map_err(Into::into)
    }

    /// Deserializes the batch, strips MAST decorators from full output note scripts, rebuilds the
    /// batch, then forwards it to the block producer.
    async fn submit_proven_tx_batch(
        &self,
        request: tonic::Request<proto::transaction::TransactionBatch>,
    ) -> Result<tonic::Response<proto::blockchain::BlockNumber>, Status> {
        let is_authorized_network_tx = self.is_authorized_network_tx(request.metadata());
        let original_accept = request.metadata().get(ACCEPT.as_str()).cloned();
        let request = request.into_inner();

        let proven_batch = ProvenBatch::read_from_bytes(&request.batch_proof).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid proven_batch"))
        })?;

        let span = Span::current();
        span.set_attribute("batch.id", proven_batch.id());
        span.set_attribute("batch.expires_at", proven_batch.batch_expiration_block_num());
        span.set_attribute("batch.reference_block.number", proven_batch.reference_block_num());
        span.set_attribute(
            "batch.reference_block.commitment",
            proven_batch.reference_block_commitment(),
        );

        let proposed_batch = request
            .proposed_batch
            .as_deref()
            .map(ProposedBatch::read_from_bytes)
            .transpose()
            .map_err(|err| {
                Status::invalid_argument(err.as_report_context("invalid proposed_batch"))
            })?
            .ok_or(Status::invalid_argument("missing `proposed_batch` field"))?;

        // Verify the reference block is actually part of the chain.
        self.verify_reference_commitment(
            proven_batch.reference_block_num(),
            proven_batch.reference_block_commitment(),
        )
        .await?;

        // Perform this check here since its cheap. If this passes we can safely zip inputs and
        // transactions.
        if request.transaction_inputs.len() != proposed_batch.transactions().len() {
            return Err(Status::invalid_argument(format!(
                "Number of inputs {} does not match number of transaction {} in batch",
                request.transaction_inputs.len(),
                proposed_batch.transactions().len()
            )));
        }

        // Same gate as `submit_proven_transaction`, applied to every post-deployment tx in the
        // batch. One store round-trip classifies all the non-deployment, public-account ids; any
        // match fails the entire batch.
        //
        // Skip this check if the client is authorized to send network transactions (ntx-builder).
        if !is_authorized_network_tx {
            let non_deployment_ids = proposed_batch
                .transactions()
                .iter()
                .filter(|tx| {
                    !tx.account_update().initial_state_commitment().is_empty()
                        && tx.account_id().is_public()
                })
                .map(|tx| tx.account_id());
            self.reject_if_any_network_accounts(non_deployment_ids).await?;
        }

        // Verify batch transaction proofs.
        //
        // Need to do this because ProvenBatch has no real kernel yet, so we can only
        // really check that the calculated proof matches the one given in the request.
        let expected_proof = spawn_blocking_in_current_span({
            let proposed_batch = proposed_batch.clone();
            move || {
                LocalBatchProver::new(MIN_PROOF_SECURITY_LEVEL).prove(proposed_batch).map_err(
                    |err| {
                        Status::invalid_argument(
                            err.as_report_context("proposed block proof failed"),
                        )
                    },
                )
            }
        })
        .await
        .map_err(|err| {
            Status::internal(format!("batch proof verification task failed: {err}"))
        })??;

        if expected_proof != proven_batch {
            return Err(Status::invalid_argument("batch proof did not match proposed batch"));
        }

        // In full node mode we forward the request to the source.
        let (block_producer, validator) = match &self.mode {
            RpcMode::Sequencer { block_producer, validator } => {
                (block_producer.as_ref(), validator.as_ref())
            },
            RpcMode::FullNode { source_rpc, .. } => {
                let mut forwarded_request = Request::new(request);
                if let Some(accept) = original_accept {
                    forwarded_request.metadata_mut().insert(ACCEPT.as_str(), accept);
                }
                return source_rpc.as_ref().clone().submit_proven_tx_batch(forwarded_request).await;
            },
        };

        // Submit each transaction to the validator.
        //
        // SAFETY: We checked earlier that the two iterators are the same length.
        for (tx, inputs) in proposed_batch.transactions().iter().zip(&request.transaction_inputs) {
            let request = proto::transaction::ProvenTransaction {
                transaction: tx.to_bytes(),
                transaction_inputs: inputs.clone().into(),
            };
            validator.clone().submit_proven_transaction(request).await?;
        }

        block_producer
            .submit_proven_tx_batch(proposed_batch)
            .await
            .map(Into::into)
            .map(Response::new)
            .map_err(Into::into)
    }

    // -- Status & utility endpoints ----------------------------------------------------------

    async fn sync_transactions(
        &self,
        request: Request<proto::rpc::SyncTransactionsRequest>,
    ) -> Result<Response<proto::rpc::SyncTransactionsResponse>, Status> {
        let range =
            read_block_range::<Status>(request.get_ref().block_range, "SyncTransactionsRequest")?;
        let n_accounts = request.get_ref().account_ids.len();
        let account_ids =
            read_account_ids::<Status, _>(request.get_ref().account_ids.iter().take(10).cloned())?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);
        span.set_attribute("account.ids", format!("{account_ids:?}").as_str());
        span.set_attribute("account.ids.count", n_accounts);

        debug!(target: COMPONENT, request = ?request);

        check::<QueryParamAccountIdLimit>(request.get_ref().account_ids.len())?;

        let request = request.into_inner();
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;
        let account_ids = read_account_ids::<Status, _>(request.account_ids)?;
        let (last_block_included, transaction_records_db) = self
            .store
            .sync_transactions(account_ids, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let transactions =
            transaction_records_db.into_iter().map(transaction_record_to_proto).collect();

        Ok(Response::new(proto::rpc::SyncTransactionsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_included.as_u32(),
            }),
            transactions,
        }))
    }

    async fn status(
        &self,
        request: Request<()>,
    ) -> Result<Response<proto::rpc::RpcStatus>, Status> {
        debug!(target: COMPONENT, request = ?request);

        let block_producer_status = match &self.mode {
            RpcMode::Sequencer { block_producer, .. } => {
                Some(block_producer_status_to_proto(block_producer.status().await))
            },
            RpcMode::FullNode { source_rpc, .. } => source_rpc
                .as_ref()
                .clone()
                .status(Request::new(()))
                .await
                .ok()
                .and_then(|response| response.into_inner().block_producer),
        };

        Ok(Response::new(proto::rpc::RpcStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            chain_tip: self.store.chain_tip(Finality::Committed).await.as_u32(),
            block_producer: block_producer_status.or(Some(proto::rpc::BlockProducerStatus {
                status: "unreachable".to_string(),
                version: "-".to_string(),
                chain_tip: 0,
                mempool_stats: Some(ProtoMempoolStats::default()),
            })),
            genesis_commitment: self.genesis_commitment.map(Into::into),
        }))
    }

    async fn get_limits(
        &self,
        request: Request<()>,
    ) -> Result<Response<proto::rpc::RpcLimits>, Status> {
        debug!(target: COMPONENT, request = ?request);

        Ok(Response::new(RPC_LIMITS.clone()))
    }

    // -- Note debugging endpoints ----------------------------------------------------------------

    async fn get_network_note_status(
        &self,
        request: Request<proto::note::NoteId>,
    ) -> Result<Response<proto::rpc::GetNetworkNoteStatusResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        let response = match &self.mode {
            RpcMode::Sequencer { .. } => {
                let Some(ntx_builder) = &self.ntx_builder else {
                    return Err(Status::unavailable("Network transaction builder is not enabled"));
                };

                ntx_builder.clone().get_network_note_status(request).await?.into_inner()
            },
            RpcMode::FullNode { source_rpc, .. } => {
                source_rpc.as_ref().clone().get_network_note_status(request).await?.into_inner()
            },
        };

        Ok(Response::new(response))
    }
}

// HELPERS
// ================================================================================================

/// Strips decorators from public output notes' scripts.
///
/// This removes MAST decorators from note scripts before forwarding to the block producer,
/// as decorators are not needed for transaction processing.
///
/// Note: `PublicOutputNote::new()` already calls `note.minify_script()` internally, so
/// reconstructing the public note through it handles decorator stripping automatically.
fn strip_output_note_decorators<'a>(
    notes: impl Iterator<Item = &'a OutputNote> + 'a,
) -> impl Iterator<Item = OutputNote> + 'a {
    notes.map(|note| match note {
        OutputNote::Public(public_note) => {
            // Reconstruct via PublicOutputNote::new which calls minify_script() internally.
            let rebuilt = PublicOutputNote::new(public_note.as_note().clone())
                .expect("rebuilding an already-valid public output note should not fail");
            OutputNote::Public(rebuilt)
        },
        OutputNote::Private(header) => OutputNote::Private(header.clone()),
    })
}

fn block_producer_status_to_proto(status: BlockProducerStatus) -> proto::rpc::BlockProducerStatus {
    proto::rpc::BlockProducerStatus {
        version: status.version,
        status: status.status,
        chain_tip: status.chain_tip.as_u32(),
        mempool_stats: Some(block_producer_mempool_stats_to_proto(status.mempool_stats)),
    }
}

fn block_producer_mempool_stats_to_proto(
    stats: BlockProducerMempoolStats,
) -> proto::rpc::MempoolStats {
    proto::rpc::MempoolStats {
        unbatched_transactions: stats.unbatched_transactions,
        proposed_batches: stats.proposed_batches,
        proven_batches: stats.proven_batches,
    }
}

fn transaction_record_to_proto(record: TransactionRecord) -> proto::rpc::TransactionRecord {
    let output_note_proofs = record
        .output_note_proofs
        .into_iter()
        .map(note_sync_record_to_proof_proto)
        .collect();

    proto::rpc::TransactionRecord {
        header: Some(proto::transaction::TransactionHeader {
            transaction_id: Some(record.header.id().into()),
            account_id: Some(record.header.account_id().into()),
            initial_state_commitment: Some(record.header.initial_state_commitment().into()),
            final_state_commitment: Some(record.header.final_state_commitment().into()),
            input_notes: record.header.input_notes().iter().cloned().map(Into::into).collect(),
            output_notes: record.header.output_notes().iter().copied().map(Into::into).collect(),
            fee: Some(Asset::from(record.header.fee()).into()),
        }),
        block_num: record.block_num.as_u32(),
        output_note_proofs,
    }
}

fn note_record_to_proto(note: NoteRecord) -> proto::note::CommittedNote {
    let inclusion_proof = Some(proto::note::NoteInclusionInBlockProof {
        note_id: Some(note.note_id.into()),
        block_num: note.block_num.as_u32(),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    let note = Some(proto::note::Note {
        metadata: Some(note.metadata.into()),
        details: note.details.map(|details| details.to_bytes()),
        attachments: note.attachments.to_bytes(),
    });
    proto::note::CommittedNote { inclusion_proof, note }
}

fn note_sync_record_to_proto(note: NoteSyncRecord) -> proto::note::NoteSyncRecord {
    let inclusion_proof = Some(proto::note::NoteInclusionInBlockProof {
        note_id: Some((&note.note_id).into()),
        block_num: note.block_num.as_u32(),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    proto::note::NoteSyncRecord {
        metadata: Some(note.metadata.into()),
        inclusion_proof,
    }
}

fn note_sync_record_to_proof_proto(note: NoteSyncRecord) -> proto::note::NoteInclusionInBlockProof {
    proto::note::NoteInclusionInBlockProof {
        note_id: Some((&note.note_id).into()),
        block_num: note.block_num.as_u32(),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    }
}

fn database_error_to_status(err: &DatabaseError) -> Status {
    let message = err.to_string();
    match err {
        DatabaseError::AccountNotFoundInDb(_)
        | DatabaseError::AccountsNotFoundInDb(_)
        | DatabaseError::AccountNotPublic(_) => Status::not_found(message),
        _ => Status::internal(message),
    }
}

fn get_block_header_error_to_status(err: GetBlockHeaderError) -> Status {
    match err {
        GetBlockHeaderError::DatabaseError(err) => database_error_to_status(&err),
        GetBlockHeaderError::MmrError(err) => Status::internal(err.to_string()),
    }
}

fn note_sync_error_to_status(err: NoteSyncError) -> Status {
    let message = err.to_string();
    match err {
        NoteSyncError::DatabaseError(err) => database_error_to_status(&err),
        NoteSyncError::InvalidBlockRange(_)
        | NoteSyncError::FutureBlock { .. }
        | NoteSyncError::DeserializationFailed(_) => Status::invalid_argument(message),
        NoteSyncError::UnderlyingDatabaseError(_)
        | NoteSyncError::EmptyBlockHeadersTable
        | NoteSyncError::MmrError(_) => Status::internal(message),
    }
}

fn get_account_error_to_status(err: GetAccountError) -> Status {
    let message = err.to_string();
    match err {
        GetAccountError::DatabaseError(err) => database_error_to_status(&err),
        GetAccountError::DeserializationFailed(_)
        | GetAccountError::AccountNotFound(..)
        | GetAccountError::AccountNotPublic(_)
        | GetAccountError::UnknownBlock(_)
        | GetAccountError::BlockPruned(_) => Status::invalid_argument(message),
    }
}

fn state_subscription_error_to_status(err: StateSubscriptionError) -> Status {
    match err {
        StateSubscriptionError::BlockNotFound(block_num) => {
            Status::not_found(format!("block {block_num} not found"))
        },
        StateSubscriptionError::ProofNotFound(block_num) => {
            Status::not_found(format!("proof for block {block_num} not found"))
        },
        StateSubscriptionError::BlockLoad { block_num, source } => {
            Status::internal(format!("failed to load block {block_num}: {}", source.as_report()))
        },
        StateSubscriptionError::ProofLoad { block_num, source } => Status::internal(format!(
            "failed to load proof for block {block_num}: {}",
            source.as_report()
        )),
        StateSubscriptionError::TooSlow => {
            Status::resource_exhausted("subscriber is too slow to keep up with the chain")
        },
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
                endpoint_limits(&[(StorageMapKeyTotal::PARAM_NAME, StorageMapKeyTotal::LIMIT)]),
            ),
        ]),
    }
});
