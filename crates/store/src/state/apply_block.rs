use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockInputs, BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Serializable;
use tracing::instrument;

use crate::COMPONENT;
use crate::errors::{ApplyBlockError, ApplyBlockWithProvingInputsError};
use crate::state::State;

impl State {
    /// Saves proving inputs for a signed block and applies it to the state.
    ///
    /// Used by the in-process block producer after it has built and signed a block.
    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn apply_block_with_proving_inputs(
        &self,
        ordered_batches: OrderedBatches,
        block_inputs: BlockInputs,
        signed_block: SignedBlock,
    ) -> Result<(), ApplyBlockWithProvingInputsError> {
        let block_header = signed_block.header().clone();
        let block_num = block_header.block_num();

        let proving_inputs = BlockProofRequest {
            tx_batches: ordered_batches,
            block_header,
            block_inputs,
        };

        self.save_proving_inputs(block_num, &proving_inputs)
            .await
            .map_err(ApplyBlockWithProvingInputsError::SaveProvingInputs)?;

        self.apply_block(signed_block)
            .await
            .map_err(ApplyBlockWithProvingInputsError::ApplyBlock)
    }

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
