use miden_block_prover::{BlockProverError as LocalBlockProverError, LocalBlockProver};
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs, BlockProof};
use miden_remote_prover_client::{RemoteBlockProver, RemoteProverClientError};

use crate::COMPONENT;

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("local proving failed")]
    LocalProvingFailed(#[source] LocalBlockProverError),
    #[error("remote proving failed")]
    RemoteProvingFailed(#[source] RemoteProverClientError),
    #[error("local proving task join error")]
    LocalProvingTaskJoin(#[source] tokio::task::JoinError),
}

// BLOCK PROVER
// ================================================================================================

/// Block prover which allows for proving via either local or remote backend.
///
/// The local proving variant is intended for development and testing purposes.
/// The remote proving variant is intended for production use.
pub enum BlockProver {
    Local(LocalBlockProver),
    Remote(RemoteBlockProver),
}

impl BlockProver {
    pub fn local() -> Self {
        Self::Local(LocalBlockProver::new(0))
    }

    pub fn remote(endpoint: impl Into<String>) -> Self {
        Self::Remote(RemoteBlockProver::new(endpoint))
    }

    #[miden_instrument(target = COMPONENT, skip_all, err)]
    pub async fn prove(
        &self,
        tx_batches: OrderedBatches,
        block_inputs: BlockInputs,
        block_header: &BlockHeader,
    ) -> Result<BlockProof, ProverError> {
        match self {
            Self::Local(prover) => {
                let prover = prover.clone();
                let block_header = block_header.clone();

                spawn_blocking_in_current_span(move || {
                    prover
                        .prove(tx_batches, &block_header, block_inputs)
                        .map_err(ProverError::LocalProvingFailed)
                })
                .await
                .map_err(ProverError::LocalProvingTaskJoin)?
            },
            Self::Remote(prover) => Ok(prover
                .prove(tx_batches, block_header, block_inputs)
                .await
                .map_err(ProverError::RemoteProvingFailed)?),
        }
    }
}
