use std::collections::BTreeSet;
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use futures::Stream;
use futures::stream::TryStreamExt;
use miden_node_proto::clients::{Builder, StoreRpcClient};
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, BlockSubscriptionResponse};
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageMapWitness, StorageSlotName};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::AccountInputs;
use miden_protocol::utils::serde::Deserializable;
use thiserror::Error;
use tracing::{info, instrument};
use url::Url;

use crate::COMPONENT;

// STORE CLIENT
// ================================================================================================

/// Thin wrapper around the store's `Rpc` gRPC service that the ntx-builder uses to consume the
/// committed-block subscription stream.
#[derive(Clone, Debug)]
pub struct StoreClient {
    inner: StoreRpcClient,
    /// Backoff schedule applied to repeated `block_subscription` connection attempts. Built once at
    /// construction time and cloned cheaply on each retry loop.
    backoff: ExponentialBuilder,
}

impl StoreClient {
    /// Creates a new store client with a lazy connection to the store's RPC endpoint.
    ///
    /// `backoff_initial` / `backoff_max` configure the exponential backoff schedule applied to
    /// `block_subscription` retries (the only operation that retries today).
    pub fn new(store_url: Url, backoff_initial: Duration, backoff_max: Duration) -> Self {
        info!(target: COMPONENT, store_endpoint = %store_url, "Initializing store client");

        let store = Builder::new(store_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<StoreRpcClient>();

        let backoff = ExponentialBuilder::default()
            .with_min_delay(backoff_initial)
            .with_max_delay(backoff_max)
            .with_factor(2.0)
            .with_jitter()
            .without_max_times();

        Self { inner: store, backoff }
    }

    /// Opens a committed-block subscription starting at `block_from`, retrying indefinitely with
    /// the client's configured exponential backoff while the initial connection attempt fails.
    ///
    /// Returns a stream that decodes each [`BlockSubscriptionResponse`] into a `(SignedBlock,
    /// committed_chain_tip)` pair. The committed chain tip is the latest block the store believes
    /// is committed at the moment the response was emitted; the ntx-builder uses it to decide
    /// when it has caught up to the live tip.
    #[instrument(
        target = COMPONENT,
        name = "store.client.block_subscription_with_retry",
        skip_all,
        fields(%block_from),
        err,
    )]
    pub async fn block_subscription_with_retry(
        &self,
        block_from: BlockNumber,
    ) -> Result<
        impl Stream<Item = Result<(SignedBlock, BlockNumber), StoreError>> + Send + 'static,
        StoreError,
    > {
        (|| async move {
            let request =
                tonic::Request::new(BlockSubscriptionRequest { block_from: block_from.as_u32() });
            let stream = self
                .inner
                .clone()
                .block_subscription(request)
                .await
                .map_err(StoreError::GrpcClientError)?
                .into_inner();

            Ok(stream
                .map_err(StoreError::GrpcClientError)
                .and_then(|response| async move { decode_block_subscription_response(&response) }))
        })
        .retry(self.backoff)
        .notify(|err: &StoreError, dur| {
            tracing::warn!(
                target: COMPONENT,
                sleep_ms = dur.as_millis() as u64,
                err = %err.as_report(),
                "store connection failed while opening block subscription, retrying",
            );
        })
        .await
    }
}

fn decode_block_subscription_response(
    response: &BlockSubscriptionResponse,
) -> Result<(SignedBlock, BlockNumber), StoreError> {
    let block = SignedBlock::read_from_bytes(&response.block).map_err(StoreError::Deserialize)?;
    let committed_tip = BlockNumber::from(response.committed_chain_tip);
    Ok((block, committed_tip))
}

// ACTOR-PATH METHODS
// ================================================================================================
//
// The actor module still references these methods. PR 1 keeps the actor code in tree as dead
// code (it is not spawned), so the methods exist as stubs to preserve compilation. PR 2 wires
// them through the appropriate store gRPC service.

#[expect(clippy::unused_async)]
impl StoreClient {
    pub async fn get_account_inputs(
        &self,
        _account_id: AccountId,
        _block_num: BlockNumber,
    ) -> Result<AccountInputs, StoreError> {
        unimplemented!("get_account_inputs is rewired in PR 2 of the ntx-builder refactor")
    }

    pub async fn get_vault_asset_witnesses(
        &self,
        _account_id: AccountId,
        _vault_keys: BTreeSet<AssetVaultKey>,
        _block_num: Option<BlockNumber>,
    ) -> Result<Vec<AssetWitness>, StoreError> {
        unimplemented!("get_vault_asset_witnesses is rewired in PR 2 of the ntx-builder refactor")
    }

    pub async fn get_storage_map_witness(
        &self,
        _account_id: AccountId,
        _slot_name: StorageSlotName,
        _map_key: StorageMapKey,
        _block_num: Option<BlockNumber>,
    ) -> Result<StorageMapWitness, StoreError> {
        unimplemented!("get_storage_map_witness is rewired in PR 2 of the ntx-builder refactor")
    }

    pub async fn get_note_script_by_root(
        &self,
        _script_root: Word,
    ) -> Result<Option<NoteScript>, StoreError> {
        unimplemented!("get_note_script_by_root is rewired in PR 2 of the ntx-builder refactor")
    }
}

// STORE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store gRPC call failed")]
    GrpcClientError(#[source] tonic::Status),
    #[error("failed to deserialize subscription payload")]
    Deserialize(#[source] miden_protocol::utils::serde::DeserializationError),
}
