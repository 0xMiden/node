use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::block::BlockNumber;

/// Moves the deposit scan cursor and returns the number of updated rows.
pub fn update_deposit_sync(
    tx: &WriteTx<'_>,
    next_sync: BlockNumber,
) -> Result<usize, DatabaseError> {
    tx.execute(include_str!("update_deposit_sync.sql"), &[&next_sync])
}
