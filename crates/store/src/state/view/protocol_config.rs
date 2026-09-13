use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::protocol_config::ProtocolConfig;

use super::StateView;
use crate::errors::{DatabaseError, RangeBeyondTip};

impl StateView {
    /// Returns the configuration commitment active at the specified block.
    ///
    /// Returns an error if the block exceeds this view's tip.
    pub async fn get_protocol_config_commitment_at(
        &self,
        block_number: BlockNumber,
    ) -> Result<Option<Word>, DatabaseError> {
        let scoped = self.scope_block(block_number).ok_or(RangeBeyondTip {
            chain_tip: *self.tip(),
            block_to: block_number,
        })?;
        self.db.select_protocol_config_commitment_at(scoped).await
    }

    /// Returns the protocol configuration with the specified commitment.
    pub async fn get_protocol_config(
        &self,
        commitment: Word,
    ) -> Result<Option<ProtocolConfig>, DatabaseError> {
        self.db.select_protocol_config_by_commitment(commitment).await
    }
}
