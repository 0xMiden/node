//! Returns the block headers for a set of block numbers.

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamBlockLimit, QueryParamLimiter};
use miden_protocol::block::{BlockHeader, BlockNumber};

use crate::db::queries::block_header_row::block_header_from_row;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_block_headers.sql");

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
