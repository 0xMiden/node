use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Serializable;

use crate::errors::ApplyBlockError;
use crate::state::State;
use crate::COMPONENT;
use tracing::instrument;

impl State {
    /// Apply changes of a new block to the DB and in-memory data structures.
    ///
    /// Forwards the block to the [`BlockWriter`](crate::state::writer::BlockWriter) task for
    /// serialised processing.
    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn apply_block(&self, signed_block: SignedBlock) -> Result<(), ApplyBlockError> {
        self.write_handle.apply_block(signed_block).await
    }

    /// Saves the proving inputs for the given block to the block store.
    pub async fn save_proving_inputs(
        &self,
        block_num: BlockNumber,
        proving_inputs: &BlockProofRequest,
    ) -> std::io::Result<()> {
        self.block_store
            .save_proving_inputs(block_num, &proving_inputs.to_bytes())
            .await
    }
}
