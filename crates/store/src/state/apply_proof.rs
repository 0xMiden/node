use anyhow::{Context, ensure};
use miden_protocol::block::{BlockNumber, BlockProof};
use miden_protocol::utils::serde::Deserializable;
use tracing::instrument;

use crate::COMPONENT;
use crate::state::{Finality, ProofNotification, State};

impl State {
    /// Saves a block proof, advances the proven-in-sequence tip, and notifies replica subscribers.
    ///
    /// # Errors
    ///
    /// - If proofs are not applied in strict ascending order (exactly one block past the proven tip)
    /// - If the proof's corresponding block was not already committed
    #[instrument(target = COMPONENT, skip_all, err, fields(block.number = block_num.as_u32()))]
    pub async fn apply_proof(
        &self,
        block_num: BlockNumber,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let expected = self.proven_tip.read().child();
        ensure!(
            block_num == expected,
            "out-of-sequence proof: expected block {expected}, got {block_num}",
        );

        let committed_tip = self.chain_tip(Finality::Committed).await;
        ensure!(
            block_num <= committed_tip,
            "proof for uncommitted block {block_num} exceeds committed tip {committed_tip}",
        );

        verify_block_proof(block_num, &proof_bytes)?;

        self.block_store.commit_proof(block_num, &proof_bytes).await?;
        self.proof_cache
            .push(block_num, ProofNotification::new(block_num, proof_bytes))
            .expect("proof cache receives sequential block numbers");
        self.proven_tip.advance(block_num);
        Ok(())
    }
}

/// Verifies that `proof_bytes` is a valid [`BlockProof`] for the block at `block_num`.
fn verify_block_proof(_block_num: BlockNumber, proof_bytes: &[u8]) -> anyhow::Result<()> {
    let _proof =
        BlockProof::read_from_bytes(proof_bytes).context("failed to deserialize block proof")?;

    // TODO: perform verification.
    Ok(())
}
