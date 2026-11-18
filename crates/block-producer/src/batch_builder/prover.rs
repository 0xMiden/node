use std::time::Duration;

use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::miden::remote_prover::v1::ProveRequest;
use miden_node_proto::generated::miden::remote_prover::v1::prove_request::Request;
use miden_node_proto::{DecodeMessage, VerifyWith};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{instrument, miden_span_record};
use miden_node_utils::retry::RetryableGrpc;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_tx_batch::{BatchExecutor, BatchVerifier, LocalBatchProver};
use url::Url;

use crate::errors::BuildBatchError;

/// Proves batches locally or through a remote prover.
#[derive(Clone)]
pub(crate) enum BatchProver {
    Local(LocalBatchProver),
    Remote(Box<RemoteProverClient>),
}

impl BatchProver {
    pub(crate) fn new() -> Self {
        Self::Local(LocalBatchProver::default().skip_precompile_proof_generation(true))
    }

    /// Connects lazily to a remote batch prover with a three-minute deadline per request.
    pub(crate) fn remote(url: Url, max_decoding_message_size: usize) -> anyhow::Result<Self> {
        let client = Builder::new(url)
            .max_decoding_message_size(max_decoding_message_size)
            .with_tls()?
            .with_timeout(Duration::from_mins(3))
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect_lazy::<RemoteProverClient>();
        Ok(Self::Remote(Box::new(client)))
    }

    #[instrument(name = "prove_batch", err)]
    pub(crate) async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, BuildBatchError> {
        let proven_batch = match self {
            Self::Local(prover) => {
                miden_span_record!(prover.kind = "local");
                let prover = prover.clone();
                spawn_blocking_in_current_span(move || {
                    let executed_batch = BatchExecutor::new()
                        .execute(proposed_batch)
                        .map_err(BuildBatchError::ProveBatchError)?;
                    prover.prove(executed_batch).map_err(BuildBatchError::ProveBatchError)
                })
                .await
                .map_err(BuildBatchError::JoinError)??
            },
            Self::Remote(client) => {
                miden_span_record!(prover.kind = "remote");
                let request = ProveRequest {
                    request: Some(Request::Batch((&proposed_batch).into())),
                };
                let response = (|| async { client.as_ref().clone().prove(request.clone()).await })
                    .retry_transient()
                    .await
                    .map_err(BuildBatchError::RemoteProvingFailed)?
                    .into_inner();
                spawn_blocking_in_current_span(move || {
                    let proven = response
                        .decode_fields()
                        .and_then(|response| response.verify_with(&proposed_batch))
                        .map_err(BuildBatchError::InvalidRemoteBatch)?;
                    BatchVerifier::new(MIN_PROOF_SECURITY_LEVEL)
                        .verify(&proven)
                        .map_err(BuildBatchError::InvalidRemoteBatchProof)?;
                    Ok::<_, BuildBatchError>(proven)
                })
                .await
                .map_err(BuildBatchError::JoinError)??
            },
        };
        if proven_batch.proof_security_level() < MIN_PROOF_SECURITY_LEVEL {
            Err(BuildBatchError::SecurityLevelTooLow(
                proven_batch.proof_security_level(),
                MIN_PROOF_SECURITY_LEVEL,
            ))
        } else {
            Ok(proven_batch)
        }
    }
}

#[cfg(test)]
mod tests;
