use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;

/// Returns the first block to include in the next deposit scan, or `None` if the cursor is missing.
pub fn select_deposit_sync(tx: &ReadTx<'_>) -> Result<Option<BlockNumber>, DatabaseError> {
    Ok(tx
        .query(include_str!("select_deposit_sync.sql"), &[], |row| row.get(0))?
        .into_iter()
        .next())
}
