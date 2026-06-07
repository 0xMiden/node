use miden_protocol::block::BlockNumber;
use tracing::instrument;

use crate::COMPONENT;
use crate::state::{ProofNotification, State};

impl State {
    /// Saves a block proof, advances the proven-in-sequence tip, and notifies replica subscribers.
    #[instrument(target = COMPONENT, skip_all, err, fields(block.number = block_num.as_u32()))]
    pub async fn apply_proof(
        &self,
        block_num: BlockNumber,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.block_store.commit_proof(block_num, &proof_bytes).await?;
        self.proof_cache
            .push(block_num, ProofNotification::new(block_num, proof_bytes))
            .expect("proof cache receives sequential block numbers");
        self.proven_tip.advance(block_num);
        Ok(())
    }
}
