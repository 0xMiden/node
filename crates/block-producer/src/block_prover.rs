use miden_block_prover::{
    BlockExecutor,
    BlockProverError as LocalBlockProverError,
    LocalBlockProver,
};
use miden_node_proto::BlockProofRequest;
use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_proto::generated::remote_prover::{Proof, ProofRequest};
use miden_node_tracing::miden_instrument;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs, ProposedBlock};
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::vm::ExecutionProof;
use url::Url;

use crate::COMPONENT;

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("failed to build proposed block")]
    ProposeBlock(#[source] ProposedBlockError),
    #[error("local proving failed")]
    LocalProvingFailed(#[source] LocalBlockProverError),
    #[error("remote proving failed")]
    RemoteProvingFailed(#[source] RemoteProverError),
    #[error("local proving task join error")]
    LocalProvingTaskJoin(#[source] tokio::task::JoinError),
}

/// Errors returned by [`RemoteBlockProver`].
#[derive(Debug, thiserror::Error)]
pub enum RemoteProverError {
    #[error("remote prover request failed")]
    Grpc(#[source] tonic::Status),
    #[error("remote prover returned an invalid block proof response: {0}")]
    Protocol(String),
    #[error("failed to decode block proof from remote prover")]
    Conversion(#[source] miden_objects::ConversionError),
}

// BLOCK PROVER
// ================================================================================================

/// Block prover which allows for proving via either local or remote backend.
///
/// The local proving variant is intended for development and testing purposes.
/// The remote proving variant is intended for production use.
pub enum BlockProver {
    Local(LocalBlockProver),
    Remote(Box<RemoteBlockProver>),
}

impl BlockProver {
    pub fn local() -> Self {
        Self::Local(LocalBlockProver::new(0))
    }

    pub fn remote(url: Url) -> anyhow::Result<Self> {
        Ok(Self::Remote(Box::new(RemoteBlockProver::new(url)?)))
    }

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    pub async fn prove(
        &self,
        tx_batches: OrderedBatches,
        block_inputs: BlockInputs,
        block_header: &BlockHeader,
    ) -> Result<ExecutionProof, ProverError> {
        match self {
            Self::Local(prover) => {
                let prover = prover.clone();
                let proposed_block = ProposedBlock::new_at(
                    block_inputs,
                    tx_batches.into_vec(),
                    block_header.timestamp(),
                )
                .map_err(ProverError::ProposeBlock)?
                .with_next_validator_config(block_header.validator_config().clone())
                .with_next_protocol_config(block_header.next_protocol_config().cloned());

                spawn_blocking_in_current_span(move || {
                    let executed_block = BlockExecutor::new()
                        .execute(proposed_block)
                        .map_err(ProverError::LocalProvingFailed)?;
                    prover.prove(executed_block).map_err(ProverError::LocalProvingFailed)
                })
                .await
                .map_err(ProverError::LocalProvingTaskJoin)?
            },
            Self::Remote(prover) => {
                let request = BlockProofRequest {
                    tx_batches,
                    block_header: block_header.clone(),
                    block_inputs,
                };
                prover.prove(request).await.map_err(ProverError::RemoteProvingFailed)
            },
        }
    }
}

// REMOTE BLOCK PROVER
// ================================================================================================

/// Thin wrapper around the remote-prover gRPC service that proves entire blocks.
///
/// The connection is lazy: the underlying channel connects on first use and is shared (cheaply
/// cloned) across all subsequent calls.
#[derive(Clone)]
pub struct RemoteBlockProver {
    client: RemoteProverClient,
}

impl RemoteBlockProver {
    /// Creates a new [`RemoteBlockProver`] with a lazy connection to the given gRPC endpoint.
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

    async fn prove(&self, request: BlockProofRequest) -> Result<ExecutionProof, RemoteProverError> {
        let request = tonic::Request::new(ProofRequest {
            request: Some(Request::Block(request.into())),
        });

        let response = self.client.clone().prove(request).await.map_err(RemoteProverError::Grpc)?;

        extract_block_proof(response.into_inner())
    }
}

fn extract_block_proof(response: Proof) -> Result<ExecutionProof, RemoteProverError> {
    match response.proof {
        Some(ProofVariant::Block(proof)) => {
            ExecutionProof::try_from(proof).map_err(RemoteProverError::Conversion)
        },
        Some(_) => Err(RemoteProverError::Protocol(
            "response variant does not match block request".to_string(),
        )),
        None => {
            Err(RemoteProverError::Protocol("response is missing the proof variant".to_string()))
        },
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn missing_block_response_variant_is_a_protocol_error() {
        let error = extract_block_proof(Proof { proof: None }).unwrap_err();

        assert!(matches!(error, RemoteProverError::Protocol(_)));
    }

    #[test]
    fn mismatched_block_response_variant_is_a_protocol_error() {
        let response = Proof {
            proof: Some(ProofVariant::Batch(
                miden_node_proto::generated::transaction::ProvenBatch::default(),
            )),
        };
        let error = extract_block_proof(response).unwrap_err();

        assert!(matches!(error, RemoteProverError::Protocol(_)));
    }
}
