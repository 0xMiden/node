use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use futures::Stream;
use futures::stream::TryStreamExt;
use miden_node_proto::clients::{Builder, RpcClient as InnerRpcClient};
use miden_node_proto::domain::account::{AccountDetails, AccountResponse};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, BlockSubscriptionResponse};
use miden_node_proto::generated::{self as proto};
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::account::{AccountCode, AccountId, PartialAccount, PartialStorage};
use miden_protocol::asset::PartialVault;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{AccountInputs, ProvenTransaction, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use thiserror::Error;
use tonic::Status;
use tonic::metadata::AsciiMetadataValue;
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
        Self::new_with_auth(rpc_url, None, backoff_initial, backoff_max)
    }

    /// Creates a new client with an optional metadata header for internal RPC authentication.
    pub fn new_with_auth(
        rpc_url: Url,
        rpc_auth_header_value: Option<AsciiMetadataValue>,
        backoff_initial: Duration,
        backoff_max: Duration,
    ) -> Self {
        info!(target: COMPONENT, rpc_endpoint = %rpc_url, "Initializing RPC client");

        let builder = Builder::new(rpc_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis();
        let builder = match rpc_auth_header_value {
            Some(value) => builder.with_auth_header_value(value),
            None => builder.without_auth_header(),
        };
        let rpc = builder.with_otel_context_injection().connect_lazy::<InnerRpcClient>();

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

// FOREIGN ACCOUNT INPUTS
// ================================================================================================

impl RpcClient {
    /// Fetches the inputs of a foreign account referenced during transaction execution.
    #[instrument(
        target = COMPONENT,
        name = "ntx.rpc.client.get_account_inputs",
        skip_all,
        err,
    )]
    pub async fn get_account_inputs(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<AccountInputs, RpcError> {
        // Request account code, account header, and storage header in order to build a minimal
        // partial account.
        let proto_request = proto::rpc::AccountRequest {
            account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
            block_num: Some(block_num.into()),
            details: Some(proto::rpc::account_request::AccountDetailRequest {
                code_commitment: Some(Word::default().into()),
                asset_vault_commitment: None,
                // No storage maps are requested for a minimal foreign account.
                storage_request: None,
            }),
        };

        let proto_response = self
            .inner
            .clone()
            .get_account(proto_request)
            .await
            .map_err(RpcError::GrpcClientError)?
            .into_inner();

        let account_response =
            AccountResponse::try_from(proto_response).map_err(RpcError::Conversion)?;

        let account_details = account_response.details.ok_or_else(|| {
            RpcError::Conversion(ConversionError::missing_field::<proto::rpc::AccountResponse>(
                "details",
            ))
        })?;
        let partial_account =
            build_minimal_foreign_account(&account_details).map_err(RpcError::Conversion)?;

        Ok(AccountInputs::new(partial_account, account_response.witness))
    }
}

/// Builds a minimal partial account from the provided account details.
///
/// The partial account is built without storage maps or an asset vault. This is intended to be used
/// to retrieve foreign account data during transaction execution.
fn build_minimal_foreign_account(
    account_details: &AccountDetails,
) -> Result<PartialAccount, ConversionError> {
    // Derive account code.
    let account_code_bytes = account_details.account_code.as_ref().ok_or_else(|| {
        ConversionError::missing_field::<proto::rpc::account_response::AccountDetails>(
            "account_code",
        )
    })?;
    let account_code = AccountCode::read_from_bytes(account_code_bytes)?;

    // Derive partial storage. Storage maps are not required for foreign accounts.
    let partial_storage = PartialStorage::new(account_details.storage_details.header.clone(), [])?;

    // Derive partial vault from vault root only.
    let partial_vault = PartialVault::new(account_details.account_header.vault_root());

    // Construct partial account.
    let partial_account = PartialAccount::new(
        account_details.account_header.id(),
        account_details.account_header.nonce(),
        account_code,
        partial_storage,
        partial_vault,
        None,
    )?;
    Ok(partial_account)
}

// NOTE SCRIPT LOOKUP
// ================================================================================================

impl RpcClient {
    /// Fetches a note script by its root from the RPC service.
    #[instrument(
        target = COMPONENT,
        name = "ntx.rpc.client.get_note_script_by_root",
        skip_all,
        err,
    )]
    pub async fn get_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, RpcError> {
        let request = proto::note::NoteScriptRoot { root: Some(root.into()) };

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
}

// RPC ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC gRPC call failed")]
    GrpcClientError(#[source] tonic::Status),
    #[error("failed to deserialize RPC payload")]
    Deserialize(#[source] miden_protocol::utils::serde::DeserializationError),
    #[error("failed to convert RPC payload")]
    Conversion(#[source] ConversionError),
}
