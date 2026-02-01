use miden_block_prover::{BlockProverError, LocalBlockProver};
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs, BlockProof};
use miden_remote_prover_client::RemoteProverClientError;
use miden_remote_prover_client::remote_prover::block_prover::RemoteBlockProver;
use tracing::instrument;

use crate::COMPONENT;

#[derive(Debug, thiserror::Error)]
pub enum StoreProverError {
    #[error("local proving failed")]
    LocalProvingFailed(#[source] BlockProverError),
    #[error("remote proving failed")]
    RemoteProvingFailed(#[source] RemoteProverClientError),
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

    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn prove(
        &self,
        tx_batches: OrderedBatches,
        block_inputs: BlockInputs,
        block_header: &BlockHeader,
    ) -> Result<BlockProof, StoreProverError> {
        match self {
            Self::Local(prover) => Ok(prover
                .prove(tx_batches, block_header, block_inputs)
                .map_err(StoreProverError::LocalProvingFailed)?),
            Self::Remote(prover) => Ok(prover
                .prove(tx_batches, block_header, block_inputs)
                .await
                .map_err(StoreProverError::RemoteProvingFailed)?),
        }
    }
}
