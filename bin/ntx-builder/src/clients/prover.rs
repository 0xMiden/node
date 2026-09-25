use std::time::Duration;

use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::remote_prover::prove_request::Request;
use miden_node_proto::generated::remote_prover::{DecodedProveResponse, ProveRequest};
use miden_node_proto::{BuildUnchecked, DecodeMessage};
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::TransactionProverError;
use url::Url;

/// Thin wrapper around the remote-prover gRPC service that proves transactions.
///
/// The connection is lazy: the underlying channel connects on first use and is shared (cheaply
/// cloned) across all subsequent calls.
#[derive(Clone)]
pub struct RemoteTransactionProver {
    client: RemoteProverClient,
}

impl RemoteTransactionProver {
    /// Creates a new [`RemoteTransactionProver`] with a lazy connection to the given gRPC endpoint.
    pub fn new(url: Url, timeout: Duration) -> anyhow::Result<Self> {
        let client = Builder::new(url)
            .with_tls()?
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect_lazy::<RemoteProverClient>();

        Ok(Self { client })
    }

    pub async fn prove(
        &self,
        tx_inputs: &TransactionInputs,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let request = tonic::Request::new(ProveRequest {
            request: Some(Request::Transaction(tx_inputs.into())),
        });

        let response = self.client.clone().prove(request).await.map_err(|err| {
            TransactionProverError::other_with_source("failed to prove transaction", err)
        })?;

        response
            .into_inner()
            .decode_fields()
            .and_then(DecodedProveResponse::into_transaction)
            // SAFETY: Construction checks transaction structure. The RPC checks the proof at
            // submission.
            //
            // FIXME: Verify the proof locally and match the response to the requested
            // execution, including its reference block and expiration, before returning success.
            .and_then(|transaction| transaction.build_unchecked().map_err(ConversionError::new))
            .map_err(|error| {
                TransactionProverError::other_with_source(
                    "invalid remote transaction proof response",
                    error,
                )
            })
    }
}
