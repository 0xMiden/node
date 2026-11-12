use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::{BlockHeader, BlockNumber};

use super::ReadTransaction;
use crate::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the header stored at `block_num`, or `None` if it is absent.
    ///
    /// Callers resolve requests for the latest block using the view's snapshot height.
    pub fn select_block_header(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<BlockHeader>, DatabaseError> {
        select_block_header(self.inner, block_num)
    }
}

/// Reads an explicit block header for transaction methods and legacy database callers.
pub(crate) fn select_block_header(
    tx: &ReadTx<'_>,
    block_num: BlockNumber,
) -> Result<Option<BlockHeader>, DatabaseError> {
    Ok(tx.query(SQL, &[&block_num], |row| row.get(0))?.into_iter().next())
}

#[cfg(test)]
mod tests;
