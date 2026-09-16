use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

/// Updates the cursor counter and retained payload size in the current transaction.
pub fn update_storage_metadata(
    tx: &WriteTx<'_>,
    next_cursor: i64,
    retained_bytes: i64,
) -> Result<(), DatabaseError> {
    tx.execute(include_str!("update_storage_metadata.sql"), &[&next_cursor, &retained_bytes])?;
    Ok(())
}
