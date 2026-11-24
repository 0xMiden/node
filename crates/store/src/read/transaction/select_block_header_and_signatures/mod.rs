use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};

use super::ReadTransaction;
use crate::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the header stored at `block_num` and the validator signatures that committed it, or
    /// `None` if the block is absent.
    pub fn select_block_header_and_signatures(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<(BlockHeader, BlockSignatures)>, DatabaseError> {
        let rows = self.inner.query(SQL, &[&block_num], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.into_iter().next())
    }
}

#[cfg(test)]
mod tests;
