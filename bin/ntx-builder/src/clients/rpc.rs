use std::collections::BTreeSet;
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use futures::Stream;
use futures::stream::TryStreamExt;
use miden_node_proto::clients::{Builder, RpcClient as InnerRpcClient};
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, BlockSubscriptionResponse};
use miden_node_proto::generated::{self as proto};
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageMapWitness, StorageSlotName};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{AccountInputs, ProvenTransaction, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use thiserror::Error;
use tonic::Status;
use tracing::{info, instrument};
use url::Url;

use crate::COMPONENT;

// RPC CLIENT
// ================================================================================================

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
    pub fn new(rpc_url: Url, backoff_initial: Duration, backoff_max: Duration) -> Self {
        info!(target: COMPONENT, rpc_endpoint = %rpc_url, "Initializing RPC client");

        let rpc = Builder::new(rpc_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<InnerRpcClient>();

        let backoff = ExponentialBuilder::default()
            .with_min_delay(backoff_initial)
            .with_max_delay(backoff_max)
            .with_factor(2.0)
            .with_jitter()
            .without_max_times();

        Self { inner: rpc, backoff }
    }

    /// Opens a committed-block subscription starting at `block_from`, retrying indefinitely with
    /// the client's configured exponential backoff while the initial connection attempt fails.
    ///
    /// Returns a stream that decodes each [`BlockSubscriptionResponse`] into a `(SignedBlock,
    /// committed_chain_tip)` pair. The committed chain tip is the latest block the node believes
    /// is committed at the moment the response was emitted; the ntx-builder uses it to decide
    /// when it has caught up to the live tip.
    #[instrument(
        target = COMPONENT,
        name = "rpc.client.block_subscription_with_retry",
        skip_all,
        fields(%block_from),
        err,
    )]
    pub async fn block_subscription_with_retry(
        &self,
        block_from: BlockNumber,
    ) -> Result<
        impl Stream<Item = Result<(SignedBlock, BlockNumber), RpcError>> + Send + 'static,
        RpcError,
    > {
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

            Ok(stream
                .map_err(RpcError::GrpcClientError)
                .and_then(|response| async move { decode_block_subscription_response(&response) }))
        })
        .retry(self.backoff)
        .notify(|err: &RpcError, dur| {
            tracing::warn!(
                target: COMPONENT,
                sleep_ms = dur.as_millis() as u64,
                err = %err.as_report(),
                "RPC connection failed while opening block subscription, retrying",
            );
        })
        .await
    }

    #[instrument(target = COMPONENT, name = "ntx.rpc.client.submit_proven_tx", skip_all, err)]
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
// The actor module still references these methods. PR 1 keeps the actor code in tree as dead
// code (it is not spawned), so the methods exist as stubs to preserve compilation. PR 2 wires
// them through the appropriate RPC gRPC service.

#[expect(clippy::unused_async)]
impl RpcClient {
    pub async fn get_account_inputs(
        &self,
        _account_id: AccountId,
        _block_num: BlockNumber,
    ) -> Result<AccountInputs, RpcError> {
        unimplemented!("get_account_inputs is rewired in PR 2 of the ntx-builder refactor")
    }

    pub async fn get_vault_asset_witnesses(
        &self,
        _account_id: AccountId,
        _vault_keys: BTreeSet<AssetVaultKey>,
        _block_num: Option<BlockNumber>,
    ) -> Result<Vec<AssetWitness>, RpcError> {
        unimplemented!("get_vault_asset_witnesses is rewired in PR 2 of the ntx-builder refactor")
    }

    pub async fn get_storage_map_witness(
        &self,
        _account_id: AccountId,
        _slot_name: StorageSlotName,
        _map_key: StorageMapKey,
        _block_num: Option<BlockNumber>,
    ) -> Result<StorageMapWitness, RpcError> {
        unimplemented!("get_storage_map_witness is rewired in PR 2 of the ntx-builder refactor")
    }

    pub async fn get_note_script_by_root(
        &self,
        _script_root: Word,
    ) -> Result<Option<NoteScript>, RpcError> {
        unimplemented!("get_note_script_by_root is rewired in PR 2 of the ntx-builder refactor")
    }
}

// RPC ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC gRPC call failed")]
    GrpcClientError(#[source] tonic::Status),
    #[error("failed to deserialize subscription payload")]
    Deserialize(#[source] miden_protocol::utils::serde::DeserializationError),
}
