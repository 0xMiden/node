use miden_protocol::Word;
use miden_protocol::block::BlockNumber;

use super::ReadTransaction;
use crate::DatabaseError;

impl ReadTransaction<'_> {
    /// Returns the commitment of the protocol configuration active at `block_num`.
    ///
    /// Returns `None` if no configuration activates at or before `block_num`.
    pub fn select_protocol_config_commitment_at(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Word>, DatabaseError> {
        crate::db::queries::select_protocol_config_commitment_at(self.inner, block_num)
    }
}
