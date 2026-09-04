//! Deletes a stored block header together with its transaction links.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;

const SQL: &str = include_str!("delete_block.sql");

/// Deletes the block header stored at `block_num`, unlinking the block's transactions via the `ON
/// DELETE CASCADE` on `block_transactions`.
pub fn delete_block(tx: &WriteTx<'_>, block_num: BlockNumber) -> Result<(), DatabaseError> {
    tx.execute(SQL, &[&block_num.to_raw_sql()])?;
    Ok(())
}
