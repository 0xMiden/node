//! Reads the latest committed block height or its header.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockHeader;

const SQL: &str = include_str!("load_chain_tip.sql");

/// Loads the chain tip (block header with the highest block number) from the database.
///
/// Returns `None` if no block headers have been persisted (i.e. bootstrap has not been run).
pub fn load_chain_tip(tx: &ReadTx<'_>) -> Result<Option<BlockHeader>, DatabaseError> {
    Ok(tx.query(SQL, &[], |row| row.get::<BlockHeader>(0))?.into_iter().next())
}

/// Returns the highest stored block number, or `None` for an empty database.
pub fn load_chain_tip_height(tx: &ReadTx<'_>) -> Result<Option<u32>, DatabaseError> {
    let sql = include_str!("load_chain_tip_height.sql");
    Ok(tx.query(sql, &[], |row| row.get::<u32>(0))?.into_iter().next())
}
