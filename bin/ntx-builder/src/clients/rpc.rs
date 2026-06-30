use std::collections::BTreeSet;
use std::time::Duration;

use backon::ExponentialBuilder;
use futures::stream::{BoxStream, TryStreamExt};
use futures::{Stream, StreamExt};
use miden_node_proto::clients::{Builder, RpcClient as InnerRpcClient};
use miden_node_proto::domain::account::{
    AccountDetails, AccountResponse, AccountVaultDetails, StorageMapEntries
};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::rpc::account_request::account_detail_request::{StorageMapDetailRequest, StorageMapDetailRequests, StorageRequest, storage_map_detail_request};
use miden_node_proto::generated::rpc::account_request::account_detail_request::storage_map_detail_request::MapKeys;
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, BlockSubscriptionResponse};
use miden_node_proto::generated::{self as proto};
use miden_node_utils::ErrorReport;
use miden_node_utils::retry::{self, Retryable};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountCode,
    AccountId,
    PartialAccount,
    PartialStorage,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetVault, AssetVaultKey, AssetWitness, PartialVault};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{AccountInputs, ProvenTransaction, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use thiserror::Error;
use tonic::Status;
use tonic::metadata::AsciiMetadataValue;
use tracing::{info};
use url::Url;

use crate::{COMPONENT, LOG_TARGET};

// RPC CLIENT
// ================================================================================================

/// A signed block paired with the node's committed chain tip at the moment the block was emitted.
type BlockSubscriptionItem = Result<(SignedBlock, BlockNumber), RpcError>;

/// Delay between block-subscription reconnect attempts, paced so a node that immediately closes the
/// connection cannot spin the reconnect loop. Connection *failures* are already backed off
/// exponentially inside [`RpcClient::block_subscription_with_retry`].
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Thin wrapper around the node RPC gRPC service that the ntx-builder uses to consume the
/// committed-block subscription stream.
#[derive(Clone, Debug)]
pub struct RpcClient {
    inner: InnerRpcClient,
    /// Backoff schedule applied to repeated `block_subscription` connection attempts. Built once at
    /// construction time and cloned cheaply on each retry loop.
    backoff: ExponentialBuilder,
}

impl RpcClient {
    /// Creates a new client with a lazy connection to the node RPC endpoint.
    ///
    /// `backoff_initial` / `backoff_max` configure the exponential backoff schedule applied to
    /// `block_subscription` retries (the only operation that retries today).
    pub fn new(
        rpc_url: Url,
        genesis_commitment: Word,
        backoff_initial: Duration,
        backoff_max: Duration,
    ) -> anyhow::Result<Self> {
        Self::new_with_auth(rpc_url, None, genesis_commitment, backoff_initial, backoff_max)
    }

    /// Creates a new client with an optional metadata header for internal RPC authentication.
    ///
    /// `genesis_commitment` is sent as the `genesis` parameter of the `Accept` header so that the
    /// node accepts write RPCs such as `SubmitProvenTx`, which require a matching genesis.
    pub fn new_with_auth(
        rpc_url: Url,
        rpc_auth_header_value: Option<AsciiMetadataValue>,
        genesis_commitment: Word,
        backoff_initial: Duration,
        backoff_max: Duration,
    ) -> anyhow::Result<Self> {
        info!(target: LOG_TARGET, rpc_endpoint = %rpc_url, "Initializing RPC client");

        let builder = Builder::new(rpc_url)
            .with_tls()?
            .without_timeout()
            .without_metadata_version()
            .with_metadata_genesis(genesis_commitment.to_hex());
        let builder = match rpc_auth_header_value {
            Some(value) => builder.with_auth_header_value(value),
            None => builder.without_auth_header(),
        };
        let rpc = builder.with_otel_context_injection().connect_lazy::<InnerRpcClient>();

        let backoff = retry::exponential(backoff_initial, backoff_max);

        Ok(Self { inner: rpc, backoff })
    }

    /// Opens a committed-block subscription starting at `block_from`, retrying indefinitely with
    /// the client's configured exponential backoff while the initial connection attempt fails.
    ///
    /// Returns a stream that decodes each [`BlockSubscriptionResponse`] into a `(SignedBlock,
    /// committed_chain_tip)` pair. The committed chain tip is the latest block the node believes
    /// is committed at the moment the response was emitted; the ntx-builder uses it to decide
    /// when it has caught up to the live tip.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "rpc.client.block_subscription_with_retry",
        skip_all,
        fields(%block_from),
        err,
    )]
    pub async fn block_subscription_with_retry(
        &self,
        block_from: BlockNumber,
    ) -> Result<BoxStream<'static, BlockSubscriptionItem>, RpcError> {
        (|| async move {
            let request =
                tonic::Request::new(BlockSubscriptionRequest { block_from: block_from.as_u32() });
            let stream = self
                .inner
                .clone()
                .block_subscription(request)
                .await
                .map_err(RpcError::GrpcClientError)?
                .into_inner();

            // Box the stream so its type is named and explicitly `'static` (it owns the cloned
            // client, borrowing nothing from `self`). This keeps the return type from capturing
            // `&self`, so callers like `block_subscription_reconnecting` can store it freely.
            Ok(stream
                .map_err(RpcError::GrpcClientError)
                .and_then(|response| async move { decode_block_subscription_response(&response) })
                .boxed())
        })
        .retry(self.backoff)
        .notify(|err: &RpcError, dur| {
            tracing::warn!(
                target: LOG_TARGET,
                sleep_ms = dur.as_millis() as u64,
                error = %err.as_report(),
                "RPC connection failed while opening block subscription, retrying",
            );
        })
        .await
    }

    /// Opens a committed-block subscription that transparently reconnects whenever the gRPC
    /// connection is closed.
    ///
    /// Each reconnection resumes from the block after the last one yielded, so no committed block
    /// is skipped or replayed. A closed or errored subscription is logged and re-opened, paced by
    /// the client's exponential backoff schedule.
    pub fn block_subscription_reconnecting(
        &self,
        block_from: BlockNumber,
    ) -> impl Stream<Item = BlockSubscriptionItem> + Send + 'static {
        let client = self.clone();

        futures::stream::unfold(
            (client, block_from, None),
            |(client, mut next_from, mut inner)| async move {
                loop {
                    // Open the subscription if we don't hold a live one. The connect itself retries
                    // indefinitely with exponential backoff.
                    let stream = match &mut inner {
                        Some(stream) => stream,
                        None => match client.block_subscription_with_retry(next_from).await {
                            Ok(stream) => inner.insert(stream),
                            Err(err) => {
                                tracing::warn!(
                                    target: LOG_TARGET, error = %err.as_report(), %next_from,
                                    "failed to open block subscription, retrying",
                                );
                                tokio::time::sleep(RECONNECT_DELAY).await;
                                continue;
                            },
                        },
                    };

                    match stream.next().await {
                        Some(Ok((block, committed_tip))) => {
                            next_from = block.header().block_num().child();
                            return Some((Ok((block, committed_tip)), (client, next_from, inner)));
                        },
                        Some(Err(err)) => tracing::warn!(
                            target: LOG_TARGET, error = %err.as_report(), %next_from,
                            "block subscription failed, reconnecting",
                        ),
                        None => tracing::warn!(
                            target: LOG_TARGET, %next_from,
                            "block subscription closed by node, reconnecting",
                        ),
                    }

                    // The subscription dropped: discard it, pace the reconnect, and resume from the
                    // next un-applied block on the following loop iteration.
                    inner = None;
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            },
        )
    }

    #[miden_node_utils::tracing::miden_instrument(target = COMPONENT, name = "ntx.rpc.client.submit_proven_tx", skip_all, err)]
    pub async fn submit_proven_tx(
        &self,
        proven_tx: &ProvenTransaction,
        tx_inputs: &TransactionInputs,
    ) -> Result<(), Status> {
        let request = proto::transaction::ProvenTransaction {
            transaction: proven_tx.to_bytes(),
            transaction_inputs: Some(tx_inputs.to_bytes()),
        };

        self.inner.clone().submit_proven_tx(request).await?;

        Ok(())
    }
}

fn decode_block_subscription_response(
    response: &BlockSubscriptionResponse,
) -> Result<(SignedBlock, BlockNumber), RpcError> {
    let block = SignedBlock::read_from_bytes(&response.block).map_err(RpcError::Deserialize)?;
    let committed_tip = BlockNumber::from(response.committed_chain_tip);
    Ok((block, committed_tip))
}

// ACTOR-PATH METHODS
// ================================================================================================
//
// Required endpoint implementations for the NTX `DataStore` implementation
impl RpcClient {
    /// Fetches the transaction inputs for a specific account.
    ///
    /// These inputs reference a specific `block_num`, and include a minimal partial account,
    /// plus its witness.
    pub async fn get_account_inputs(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<AccountInputs, RpcError> {
        // Only request account code
        let request = proto::rpc::AccountRequest {
            account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
            block_num: Some(block_num.into()),
            // TODO: should these commitments be cached on the NTX builder?
            details: Some(proto::rpc::account_request::AccountDetailRequest {
                code_commitment: Some(Word::default().into()),
                asset_vault_commitment: None, //
                storage_request: None,
            }),
        };

        let response = self.get_account(request).await?;
        let details = response.details.as_ref().ok_or_else(|| {
            RpcError::InvalidResponse("response did not include account details".into())
        })?;
        let partial_account = build_minimal_partial_account(details)?;

        Ok(AccountInputs::new(partial_account, response.witness))
    }

    /// Fetches asset vault witnesses for the given keys at the reference block.
    pub async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_keys: BTreeSet<AssetVaultKey>,
        block_num: Option<BlockNumber>,
    ) -> Result<Vec<AssetWitness>, RpcError> {
        if vault_keys.is_empty() {
            return Ok(Vec::new());
        }

        let request = proto::rpc::AccountRequest {
            account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
            block_num: block_num.map(Into::into),
            details: Some(proto::rpc::account_request::AccountDetailRequest {
                code_commitment: None,
                asset_vault_commitment: Some(Word::default().into()),
                storage_request: None,
            }),
        };

        let response = self.get_account(request).await?;
        let assets: Vec<Asset> = match response.details.map(|details| details.vault_details) {
            Some(AccountVaultDetails::Assets(assets)) => assets,
            Some(AccountVaultDetails::LimitExceeded) => {
                // NOTE: in the tx kernel, `get_vault_asset_witnesses` is called either for single
                // asset keys, or when pre-loading all the assets related to input notes involved in
                // the transaction. This should never exceed the maximum amount of keys you can
                // request to RPC, but this needs double-checking. If it able to exceed them,
                // batching needs to be implemented as a workaround.
                panic!("should never exceed maximum number of requested keys")
            },
            None => Vec::new(),
        };

        let vault =
            AssetVault::new(&assets).map_err(|err| RpcError::InvalidResponse(err.as_report()))?;

        Ok(vault_keys.into_iter().map(|key| vault.open(key)).collect())
    }

    /// Fetches a storage map witness for a single key at the reference block.
    pub async fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        map_key: StorageMapKey,
        block_num: Option<BlockNumber>,
    ) -> Result<StorageMapWitness, RpcError> {
        let request = proto::rpc::AccountRequest {
            account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
            block_num: block_num.map(Into::into),
            details: Some(proto::rpc::account_request::AccountDetailRequest {
                code_commitment: None,
                asset_vault_commitment: None,
                storage_request: Some(StorageRequest::StorageMaps(StorageMapDetailRequests {
                    storage_maps: vec![StorageMapDetailRequest {
                        slot_name: slot_name.to_string(),
                        slot_data: Some(storage_map_detail_request::SlotData::MapKeys(MapKeys {
                            map_keys: vec![map_key.into()],
                        })),
                    }],
                })),
            }),
        };

        let response = self.get_account(request).await?;
        let details = response.details.as_ref().ok_or_else(|| {
            RpcError::InvalidResponse("response did not include account details".into())
        })?;

        let map_details = details
            .storage_details
            .map_details
            .iter()
            .find(|detail| detail.slot_name == slot_name)
            .ok_or_else(|| {
                RpcError::InvalidResponse(format!(
                    "response is missing storage map details for slot {slot_name}"
                ))
            })?;

        let StorageMapEntries::EntriesWithProofs(proofs) = &map_details.entries else {
            return Err(RpcError::InvalidResponse(
                "response did not include storage map entry proofs".into(),
            ));
        };

        let proof = proofs.first().cloned().ok_or_else(|| {
            RpcError::InvalidResponse(
                "response did not include a proof for the requested key".into(),
            )
        })?;

        StorageMapWitness::new(proof, [map_key])
            .map_err(|err| RpcError::InvalidResponse(err.as_report()))
    }

    /// Fetches a note script by its root, returning `None` if the node does not know it.
    #[miden_node_utils::tracing::miden_instrument(target = COMPONENT, name = "ntx.rpc.client.get_note_script_by_root", skip_all, err)]
    pub async fn get_note_script_by_root(
        &self,
        script_root: Word,
    ) -> Result<Option<NoteScript>, RpcError> {
        let request = proto::note::NoteScriptRoot { root: Some(script_root.into()) };

        let script = self
            .inner
            .clone()
            .get_note_script_by_root(request)
            .await
            .map_err(RpcError::GrpcClientError)?
            .into_inner()
            .script;

        script.map(NoteScript::try_from).transpose().map_err(RpcError::Conversion)
    }

    /// Issues a `GetAccount` request and decodes the response into the domain [`AccountResponse`].
    async fn get_account(
        &self,
        request: proto::rpc::AccountRequest,
    ) -> Result<AccountResponse, RpcError> {
        let response = self
            .inner
            .clone()
            .get_account(request)
            .await
            .map_err(RpcError::GrpcClientError)?
            .into_inner();

        AccountResponse::try_from(response).map_err(RpcError::Conversion)
    }
}

/// Builds a minimal partial account from account details.
fn build_minimal_partial_account(details: &AccountDetails) -> Result<PartialAccount, RpcError> {
    let code_bytes = details
        .account_code
        .as_ref()
        .ok_or_else(|| RpcError::InvalidResponse("response did not include account code".into()))?;
    let account_code = AccountCode::read_from_bytes(code_bytes).map_err(RpcError::Deserialize)?;

    let partial_storage = PartialStorage::new(details.storage_details.header.clone(), [])
        .map_err(|err| RpcError::InvalidResponse(err.as_report()))?;

    let partial_vault = PartialVault::new(details.account_header.vault_root());

    PartialAccount::new(
        details.account_header.id(),
        details.account_header.nonce(),
        account_code,
        partial_storage,
        partial_vault,
        None,
    )
    .map_err(|err| RpcError::InvalidResponse(err.as_report()))
}

// RPC ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC gRPC call failed")]
    GrpcClientError(#[source] tonic::Status),
    #[error("failed to deserialize RPC payload")]
    Deserialize(#[source] miden_protocol::utils::serde::DeserializationError),
    #[error("failed to convert RPC response")]
    Conversion(#[source] ConversionError),
    #[error("invalid RPC response: {0}")]
    InvalidResponse(String),
}
