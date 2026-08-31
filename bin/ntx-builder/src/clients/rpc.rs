use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use backon::ExponentialBuilder;
use futures::stream::{BoxStream, TryStreamExt};
use futures::{Stream, StreamExt};
use miden_node_proto::clients::{Builder, RpcClient as InnerRpcClient};
use miden_node_proto::domain::account::{
    AccountDetails, AccountResponse, AccountVaultDetails, StorageMapEntries
};
use miden_node_proto::domain::encryption::{
    TransactionInputsSealer,
    TrustedTransactionEncryptionState,
    verify_transaction_encryption_key,
};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::rpc::account_request::account_detail_request::{StorageMapDetailRequest, StorageMapDetailRequests, StorageRequest, storage_map_detail_request};
use miden_node_proto::generated::rpc::account_request::account_detail_request::storage_map_detail_request::MapKeys;
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, BlockSubscriptionResponse};
use miden_node_proto::generated::{self as proto};
use miden_node_tracing::ErrorReport;
use miden_node_utils::retry::{self, Retryable};
use miden_node_tracing::{debug, info, miden_instrument, warn};
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
use miden_protocol::asset::{Asset, AssetVault, AssetId, AssetWitness, PartialVault};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{AccountInputs, ProvenTransaction, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use thiserror::Error;
use tonic::Status;
use tonic::metadata::AsciiMetadataValue;
use url::Url;

use crate::COMPONENT;

// RPC CLIENT
// ================================================================================================

/// A signed block paired with the node's committed chain tip at the moment the block was emitted.
type BlockSubscriptionItem = Result<(SignedBlock, BlockNumber), RpcError>;

/// Delay between block-subscription reconnect attempts, paced so a node that immediately closes the
/// connection cannot spin the reconnect loop. Connection *failures* are already backed off
/// exponentially inside [`RpcClient::block_subscription_with_retry`].
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// How long a single `stream.next()` poll waits before re-evaluating liveness.
const BLOCK_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time without a committed block before treating the subscription as stalled and forcing a
/// reconnect.
///
/// This is a defensive backstop for a silently dropped connection that never surfaces an error on
/// its own (client HTTP/2 keepalive is the primary, faster detector). It must be comfortably larger
/// than the node's block interval so a legitimately quiet chain is not mistaken for a stall.
const STALL_TIMEOUT: Duration = Duration::from_mins(2);

/// Thin wrapper around the node RPC gRPC service that the ntx-builder uses to consume the
/// committed-block subscription stream.
#[derive(Clone, Debug)]
pub struct RpcClient {
    inner: InnerRpcClient,
    /// Backoff schedule applied to repeated `block_subscription` connection attempts. Built once at
    /// construction time and cloned cheaply on each retry loop.
    backoff: ExponentialBuilder,
    /// Genesis commitment of the network being submitted to, bound into the associated data of
    /// sealed transaction inputs.
    genesis_commitment: Word,
    /// Cached sealer for transaction inputs, fetched on first submission.
    sealer: Arc<RwLock<Option<TransactionInputsSealer>>>,
    /// Validator signing keys read from the genesis block at bootstrap.
    trusted_validator_signing_keys: Arc<[ValidatorPublicKey]>,
}

impl RpcClient {
    /// Creates a new client with a lazy connection to the node RPC endpoint.
    ///
    /// `request_timeout` bounds each gRPC request, including establishment of the long-lived block
    /// subscription but not the lifetime of its response stream.
    ///
    /// `backoff_initial` / `backoff_max` configure the exponential backoff schedule applied to
    /// `block_subscription` retries (the only operation that retries today).
    pub fn new(
        rpc_url: Url,
        genesis_commitment: Word,
        trusted_validator_signing_keys: Vec<ValidatorPublicKey>,
        request_timeout: Duration,
        backoff_initial: Duration,
        backoff_max: Duration,
    ) -> anyhow::Result<Self> {
        Self::new_with_auth(
            rpc_url,
            None,
            genesis_commitment,
            trusted_validator_signing_keys,
            request_timeout,
            backoff_initial,
            backoff_max,
        )
    }

    /// Creates a new client with an optional metadata header for internal RPC authentication.
    ///
    /// `genesis_commitment` is sent as the `genesis` parameter of the `Accept` header so that the
    /// node accepts write RPCs such as `SubmitProvenTx`, which require a matching genesis.
    pub fn new_with_auth(
        rpc_url: Url,
        rpc_auth_header_value: Option<AsciiMetadataValue>,
        genesis_commitment: Word,
        trusted_validator_signing_keys: Vec<ValidatorPublicKey>,
        request_timeout: Duration,
        backoff_initial: Duration,
        backoff_max: Duration,
    ) -> anyhow::Result<Self> {
        info!(
            target: COMPONENT,
            "Initializing RPC client",
            dependency.name = "rpc",
            dependency.endpoint = rpc_url.to_string()
        );

        let builder = Builder::new(rpc_url)
            .with_tls()?
            .with_timeout(request_timeout)
            .without_metadata_version()
            .with_metadata_genesis(genesis_commitment);
        let builder = match rpc_auth_header_value {
            Some(value) => builder.with_auth_header_value(value),
            None => builder.without_auth_header(),
        };
        let rpc = builder.with_otel_context_injection().connect_lazy::<InnerRpcClient>();

        let backoff = retry::exponential(backoff_initial, backoff_max);

        Ok(Self {
            inner: rpc,
            backoff,
            genesis_commitment,
            sealer: Arc::new(RwLock::new(None)),
            trusted_validator_signing_keys: trusted_validator_signing_keys.into(),
        })
    }

    /// Returns a sealer for transaction inputs, fetching the encryption key if the cache is empty.
    pub(crate) async fn sealer(&self) -> Result<TransactionInputsSealer, Status> {
        if let Some(sealer) = self.sealer.read().await.clone() {
            return Ok(sealer);
        }

        let key = self.inner.clone().get_transaction_encryption_key(()).await?.into_inner();
        let verified = verify_transaction_encryption_key(
            key,
            TrustedTransactionEncryptionState::new(
                self.genesis_commitment,
                &self.trusted_validator_signing_keys,
            ),
        )
        .map_err(|err| {
            Status::failed_precondition(
                err.as_report_context("Untrusted transaction encryption key"),
            )
        })?;
        let sealer = TransactionInputsSealer::new(verified);

        let mut cached = self.sealer.write().await;
        if let Some(sealer) = cached.clone() {
            return Ok(sealer);
        }
        *cached = Some(sealer.clone());
        Ok(sealer)
    }

    /// Opens a committed-block subscription starting at `block_from`, retrying indefinitely with
    /// the client's configured exponential backoff while the initial connection attempt fails.
    ///
    /// Returns a stream that decodes each [`BlockSubscriptionResponse`] into a `(SignedBlock,
    /// committed_chain_tip)` pair. The committed chain tip is the latest block the node believes
    /// is committed at the moment the response was emitted; the ntx-builder uses it to decide
    /// when it has caught up to the live tip.
    #[miden_instrument(
        target = COMPONENT,
        name = "rpc.client.block_subscription_with_retry",
        fields(
            block.from = block_from,
        ),
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
            warn!(
                err,
                target: COMPONENT,
                "RPC connection failed while opening block subscription, retrying",
                retry.delay_ms = dur.as_millis() as u64
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
            (client, block_from, None, Instant::now()),
            |(client, mut next_from, mut inner, mut last_block)| async move {
                loop {
                    // Open the subscription if we don't hold a live one. The connect itself retries
                    // indefinitely with exponential backoff.
                    let stream = match &mut inner {
                        Some(stream) => stream,
                        None => match client.block_subscription_with_retry(next_from).await {
                            Ok(stream) => {
                                info!(
                                    target: COMPONENT,
                                    "block subscription connected",
                                    block.from = next_from
                                );
                                // Reset the stall clock so time spent (re)connecting is not counted
                                // against the next block's arrival.
                                last_block = Instant::now();
                                inner.insert(stream)
                            },
                            Err(err) => {
                                warn!(
                                    &err,
                                    target: COMPONENT,
                                    "failed to open block subscription, retrying",
                                    block.from = next_from
                                );
                                tokio::time::sleep(RECONNECT_DELAY).await;
                                continue;
                            },
                        },
                    };

                    // Poll on a short timeout so a silently dropped connection stays observable.
                    // Each quiet poll emits a liveness log; once no block has arrived for
                    // `STALL_TIMEOUT` the subscription is treated as stalled and reconnected.
                    match tokio::time::timeout(BLOCK_POLL_TIMEOUT, stream.next()).await {
                        Ok(Some(Ok((block, committed_tip)))) => {
                            next_from = block.header().block_num().child();
                            last_block = Instant::now();
                            return Some((
                                Ok((block, committed_tip)),
                                (client, next_from, inner, last_block),
                            ));
                        },
                        Ok(Some(Err(err))) => warn!(
                            &err,
                            target: COMPONENT,
                            "block subscription failed, reconnecting",
                            block.from = next_from
                        ),
                        Ok(None) => warn!(
                            target: COMPONENT,
                            "block subscription closed by node, reconnecting",
                            block.from = next_from
                        ),
                        Err(_elapsed) => {
                            let idle = last_block.elapsed();
                            if idle < STALL_TIMEOUT {
                                // Quiet but not yet stalled: emit a liveness signal and keep
                                // polling the same stream instead of reconnecting.
                                debug!(
                                    target: COMPONENT,
                                    "no block received recently; subscription still open",
                                    block.from = next_from,
                                    subscription.idle_ms = idle.as_millis() as u64
                                );
                                continue;
                            }
                            warn!(
                                target: COMPONENT,
                                "no block received within stall timeout; treating subscription as stalled, reconnecting",
                                block.from = next_from,
                                subscription.idle_ms = idle.as_millis() as u64,
                                subscription.stall_timeout_ms = STALL_TIMEOUT.as_millis() as u64
                            );
                        },
                    }

                    // Reached on an error/close/stall branch: discard the stream, pace the
                    // reconnect, and resume from the next un-applied block on the following
                    // iteration.
                    inner = None;
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            },
        )
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "ntx.rpc.client.submit_proven_tx",
        err,
    )]
    pub async fn submit_proven_tx(
        &self,
        proven_tx: &ProvenTransaction,
        tx_inputs: &TransactionInputs,
    ) -> Result<(), Status> {
        let transaction: proto::transaction::ProvenTransactionData = proven_tx.into();
        let transaction_inputs = tx_inputs.to_bytes();
        let tx_id = proven_tx.id();
        let stale_key = AtomicBool::new(false);

        (|| {
            let mut client = self.inner.clone();
            let transaction = transaction.clone();
            let transaction_inputs = transaction_inputs.clone();
            let stale_key = &stale_key;
            async move {
                if stale_key.swap(false, Ordering::Relaxed) {
                    *self.sealer.write().await = None;
                }

                let sealer = self.sealer().await?;
                let sealed = sealer.seal(tx_id, &transaction_inputs).map_err(|err| {
                    Status::failed_precondition(
                        err.as_report_context("Failed to seal the transaction inputs"),
                    )
                })?;
                client
                    .submit_proven_tx(proto::submission::ProvenTransactionSubmission {
                        transaction: Some(transaction),
                        sealed_transaction_inputs: Some(sealed),
                    })
                    .await
            }
        })
        .retry(retry::constant(Duration::ZERO, Some(1)))
        .when(|status: &Status| status.code() == tonic::Code::FailedPrecondition)
        .notify(|status: &Status, _| {
            stale_key.store(true, Ordering::Relaxed);
            warn!(
                status,
                target: COMPONENT,
                "Transaction inputs rejected as stale, refreshing the encryption key and retrying",
                transaction.id = tx_id
            );
        })
        .await
        .map(|_| ())
    }
}

fn decode_block_subscription_response(
    response: &BlockSubscriptionResponse,
) -> Result<(SignedBlock, BlockNumber), RpcError> {
    let block = response
        .block
        .clone()
        .ok_or_else(|| {
            RpcError::InvalidResponse("block subscription response is missing block".into())
        })?
        .try_into()
        .map_err(ConversionError::from)
        .map_err(RpcError::Conversion)?;
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
        vault_keys: BTreeSet<AssetId>,
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
                            map_keys: vec![map_key.as_word().into()],
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

        let StorageMapEntries::PartialMap { map_keys, partial_smt } = &map_details.entries else {
            return Err(RpcError::InvalidResponse(
                "response did not include a partial storage map".into(),
            ));
        };

        if !map_keys.contains(&map_key) {
            return Err(RpcError::InvalidResponse(
                "response partial storage map did not include the requested key".into(),
            ));
        }

        let proof = partial_smt.open(&map_key.hash().as_word()).map_err(|err| {
            RpcError::InvalidResponse(format!(
                "response did not track the requested storage map key: {err}"
            ))
        })?;

        StorageMapWitness::new(proof, [map_key])
            .map_err(|err| RpcError::InvalidResponse(err.as_report()))
    }

    /// Fetches a note script by its root, returning `None` if the node does not know it.
    #[miden_instrument(
        target = COMPONENT,
        name = "ntx.rpc.client.get_note_script_by_root",
        err,
    )]
    pub async fn get_note_script_by_root(
        &self,
        script_root: Word,
    ) -> Result<Option<NoteScript>, RpcError> {
        let request: proto::primitives::Word = script_root.into();

        let script = self
            .inner
            .clone()
            .get_note_script_by_root(request)
            .await
            .map_err(RpcError::GrpcClientError)?
            .into_inner()
            .script;

        script
            .map(NoteScript::try_from)
            .transpose()
            .map_err(|err| RpcError::Conversion(err.into()))
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
