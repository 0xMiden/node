use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_node_tracing::instrument;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockInputs, BlockNumber, SignedBlock};

use crate::errors::ApplyBlockWithProvingInputsError;
use crate::state::BlockWriter;
use crate::validator_config::ValidatorConfigGuard;

impl BlockWriter {
    /// Saves proving inputs for a signed block and applies it to the state.
    ///
    /// Used by the in-process block producer after it has built and signed a block.
    #[instrument(err)]
    pub async fn apply_block_with_proving_inputs(
        &mut self,
        ordered_batches: OrderedBatches,
        block_inputs: BlockInputs,
        signed_block: SignedBlock,
    ) -> Result<(), ApplyBlockWithProvingInputsError> {
        self.apply_block_with_inputs(ordered_batches, block_inputs, signed_block, None)
            .await
    }

    /// Saves and commits a sequencer block while holding its validator configuration lock.
    ///
    /// The write worker keeps the lock until it publishes the committed block, including when
    /// the caller is cancelled. A successful transition clears the pending change before unlocking.
    #[instrument(err)]
    pub async fn apply_sequencer_block(
        &mut self,
        ordered_batches: OrderedBatches,
        block_inputs: BlockInputs,
        signed_block: SignedBlock,
        validator_config_guard: ValidatorConfigGuard,
    ) -> Result<(), ApplyBlockWithProvingInputsError> {
        self.apply_block_with_inputs(
            ordered_batches,
            block_inputs,
            signed_block,
            Some(validator_config_guard),
        )
        .await
    }

    async fn apply_block_with_inputs(
        &mut self,
        ordered_batches: OrderedBatches,
        block_inputs: BlockInputs,
        signed_block: SignedBlock,
        validator_config_guard: Option<ValidatorConfigGuard>,
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

        self.apply_block_with_guard(signed_block, None, validator_config_guard)
            .await
            .map_err(ApplyBlockWithProvingInputsError::ApplyBlock)
    }

    /// Saves the proving inputs for the given block to the block store.
    pub async fn save_proving_inputs(
        &self,
        block_num: BlockNumber,
        proving_inputs: &BlockProofRequest,
    ) -> std::io::Result<()> {
        self.block_store
            .save_proving_inputs(block_num, &miden_node_persistence::encode(proving_inputs))
            .await
    }
}
