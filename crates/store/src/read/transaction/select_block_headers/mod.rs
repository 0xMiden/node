use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamBlockLimit, QueryParamLimiter};
use miden_protocol::block::{BlockHeader, BlockNumber};

use super::ReadTransaction;
use super::block_header_row::block_header_from_row;
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
        select_block_headers(self.inner, blocks)
    }
}

/// Returns the block headers stored at `blocks`, ordered by block number.
///
/// The result does not include block numbers that have no stored header, so it can be shorter
/// than `blocks`.
///
/// # Parameters
///
/// * `blocks`: the block numbers to retrieve, at most [`QueryParamBlockLimit`] of them.
pub(crate) fn select_block_headers(
    tx: &ReadTx<'_>,
    blocks: impl Iterator<Item = BlockNumber> + Send,
) -> Result<Vec<BlockHeader>, DatabaseError> {
    QueryParamBlockLimit::check(blocks.size_hint().0)?;

    let blocks = InList::from_values(blocks);

    Ok(tx.query(SQL, &[&blocks], block_header_from_row)?)
}

#[cfg(test)]
mod tests;
