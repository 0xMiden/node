use miden_block_prover::{
    BlockExecutor,
    BlockProverError as LocalBlockProverError,
    LocalBlockProver,
};
use miden_node_proto::BlockProofRequest;
use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::{ProofRequest, ProofType};
use miden_node_tracing::miden_instrument;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs, ProposedBlock};
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::utils::serde::{Deserializable, DeserializationError, Serializable};
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
    #[error("failed to build proposed block")]
    ProposeBlock(#[source] ProposedBlockError),
    #[error("remote prover request failed")]
    Grpc(#[source] tonic::Status),
    #[error("failed to deserialize block proof from remote prover")]
    Deserialize(#[source] DeserializationError),
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
        Self::Local(LocalBlockProver::default())
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
            Self::Remote(prover) => prover
                .prove(tx_batches, block_header, block_inputs)
                .await
                .map_err(ProverError::RemoteProvingFailed),
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

    async fn prove(
        &self,
        tx_batches: OrderedBatches,
        block_header: &BlockHeader,
        block_inputs: BlockInputs,
    ) -> Result<ExecutionProof, RemoteProverError> {
        let proof_request = BlockProofRequest {
            tx_batches,
            block_header: block_header.clone(),
            block_inputs,
        };

        let request = tonic::Request::new(ProofRequest {
            proof_type: ProofType::Block.into(),
            payload: proof_request.to_bytes(),
        });

        let response = self.client.clone().prove(request).await.map_err(RemoteProverError::Grpc)?;

        ExecutionProof::read_from_bytes(&response.into_inner().payload)
            .map_err(RemoteProverError::Deserialize)
    }
}
