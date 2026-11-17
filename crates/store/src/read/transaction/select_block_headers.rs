use miden_protocol::block::{BlockHeader, BlockNumber};

use super::ReadTransaction;
use crate::DatabaseError;

impl ReadTransaction<'_> {
    /// Returns the headers stored at `blocks`, ordered by block number.
    ///
    /// Blocks without a stored header are omitted, so the result can be shorter than `blocks`.
    pub fn select_block_headers(
        &self,
        blocks: impl Iterator<Item = BlockNumber> + Send,
    ) -> Result<Vec<BlockHeader>, DatabaseError> {
        crate::db::queries::select_block_headers(self.inner, blocks)
    }
}
