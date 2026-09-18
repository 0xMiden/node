use miden_node_proto::DecodeMessageExt;
use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::ProofRequest;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_tx_batch::{BatchExecutor, LocalBatchProver};
use url::Url;

use crate::COMPONENT;
use crate::errors::BuildBatchError;

/// Errors returned by [`RemoteBatchProver`].
#[derive(Debug, thiserror::Error)]
pub enum RemoteProverError {
    #[error("remote prover request failed")]
    Grpc(#[source] tonic::Status),
    #[error("failed to decode proven batch from remote prover")]
    Conversion(#[source] miden_node_proto::errors::ConversionError),
}

// BATCH PROVER
// ================================================================================================

/// Represents a batch prover which can be either local or remote.
#[derive(Clone)]
pub(crate) enum BatchProver {
    Local(LocalBatchProver),
    Remote(Box<RemoteBatchProver>),
}

impl BatchProver {
    #[miden_instrument(target = COMPONENT, name = "batch_builder.prove_batch", err)]
    pub(crate) async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, BuildBatchError> {
        miden_span_record!(prover.kind = self.kind());
        let proven_batch = match self {
            Self::Remote(prover) => prover
                .prove(proposed_batch)
                .await
                .map_err(BuildBatchError::RemoteProverClientError),
            Self::Local(prover) => {
                let prover = prover.clone();
                spawn_blocking_in_current_span(move || {
                    let executed_batch = BatchExecutor::new()
                        .execute(proposed_batch)
                        .map_err(BuildBatchError::ProveBatchError)?;
                    prover.prove(executed_batch).map_err(BuildBatchError::ProveBatchError)
                })
                .await
                .map_err(BuildBatchError::JoinError)?
            },
        }?;
        if proven_batch.proof_security_level() < MIN_PROOF_SECURITY_LEVEL {
            Err(BuildBatchError::SecurityLevelTooLow(
                proven_batch.proof_security_level(),
                MIN_PROOF_SECURITY_LEVEL,
            ))
        } else {
            Ok(proven_batch)
        }
    }

    pub(super) const fn kind(&self) -> &'static str {
        match self {
            BatchProver::Local(_) => "local",
            BatchProver::Remote(_) => "remote",
        }
    }

    pub(crate) fn local() -> Self {
        Self::Local(LocalBatchProver::default())
    }

    pub(super) fn remote(url: Url) -> anyhow::Result<Self> {
        Ok(Self::Remote(Box::new(RemoteBatchProver::new(url)?)))
    }
}

// REMOTE BATCH PROVER
// ================================================================================================

/// Thin wrapper around the remote-prover gRPC service that proves transaction batches.
///
/// The connection is lazy: the underlying channel connects on first use and is shared (cheaply
/// cloned) across all subsequent calls.
#[derive(Clone)]
pub(crate) struct RemoteBatchProver {
    client: RemoteProverClient,
}

impl RemoteBatchProver {
    /// Creates a new [`RemoteBatchProver`] with a lazy connection to the given gRPC endpoint.
    fn new(url: Url) -> anyhow::Result<Self> {
        let client = Builder::new(url)
            .with_tls()?
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect_lazy::<RemoteProverClient>();

        Ok(Self { client })
    }

    pub(super) async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, RemoteProverError> {
        let request = tonic::Request::new(ProofRequest {
            request: Some(Request::Batch((&proposed_batch).into())),
        });

        let response = self.client.clone().prove(request).await.map_err(RemoteProverError::Grpc)?;
        response
            .into_inner()
            .decode_and_verify_with(&proposed_batch)
            .map_err(RemoteProverError::Conversion)
    }
}
