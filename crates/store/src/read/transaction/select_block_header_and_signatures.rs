use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};

use super::ReadTransaction;
use crate::DatabaseError;

impl ReadTransaction<'_> {
    /// Returns the header stored at `block_num` and the validator signatures that committed it, or
    /// `None` if the block is absent.
    pub fn select_block_header_and_signatures(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<(BlockHeader, BlockSignatures)>, DatabaseError> {
        crate::db::queries::select_block_header_and_signatures_by_block_num(self.inner, block_num)
    }
}
