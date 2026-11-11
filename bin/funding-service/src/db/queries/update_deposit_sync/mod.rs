use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::block::BlockNumber;

/// Sets the first block to include in the next deposit scan and returns the number of updated rows.
pub fn update_deposit_sync(
    tx: &WriteTx<'_>,
    next_sync: BlockNumber,
) -> Result<usize, DatabaseError> {
    tx.execute(include_str!("update_deposit_sync.sql"), &[&next_sync])
}
