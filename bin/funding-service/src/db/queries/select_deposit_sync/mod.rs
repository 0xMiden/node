use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;

/// Reads the first block the next deposit scan reads.
pub fn select_deposit_sync(tx: &ReadTx<'_>) -> Result<Option<BlockNumber>, DatabaseError> {
    Ok(tx
        .query(include_str!("select_deposit_sync.sql"), &[], |row| row.get(0))?
        .into_iter()
        .next())
}
