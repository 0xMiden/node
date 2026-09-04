//! Persists a block header that this validator has signed.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockHeader;

const SQL: &str = include_str!("insert_block_header.sql");

/// Inserts a block header at its height, which must not already hold one; when replacing a block,
/// [`delete_block`](super::delete_block) the old header first.
pub fn insert_block_header(tx: &WriteTx<'_>, header: &BlockHeader) -> Result<(), DatabaseError> {
    tx.execute(SQL, &[&header.block_num().to_raw_sql(), header])?;
    Ok(())
}
