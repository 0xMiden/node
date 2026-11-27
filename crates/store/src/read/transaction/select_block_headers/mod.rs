use miden_node_db::sqlite::InList;
use miden_node_utils::limiter::{QueryParamBlockLimit, QueryParamLimiter};
use miden_protocol::block::{BlockHeader, BlockNumber};

use super::ReadTransaction;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the headers stored at `blocks`, ordered by block number.
    ///
    /// Blocks without a stored header are omitted, so the result can be shorter than `blocks`.
    pub fn select_block_headers(
        &self,
        blocks: impl Iterator<Item = BlockNumber> + Send,
    ) -> Result<Vec<BlockHeader>, DatabaseError> {
        QueryParamBlockLimit::check(blocks.size_hint().0)?;

        let blocks = InList::from_values(blocks);

        Ok(self.inner.query(SQL, &[&blocks], |row| row.get(0))?)
    }
}

#[cfg(test)]
mod tests;
