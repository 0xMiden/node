//! Reads the latest block header visible to a SQLite transaction.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockHeader;

use super::block_header_row::block_header_from_row;
use crate::DatabaseError;

const SQL: &str = include_str!("query.sql");

/// Returns the chain tip, or `None` if the database contains no blocks.
pub(crate) fn select_chain_tip(tx: &ReadTx<'_>) -> Result<Option<BlockHeader>, DatabaseError> {
    Ok(tx.query(SQL, &[], block_header_from_row)?.into_iter().next())
}

#[cfg(test)]
mod tests;
