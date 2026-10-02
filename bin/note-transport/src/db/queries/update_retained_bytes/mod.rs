use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

/// Updates the retained payload size in the current transaction.
pub fn update_retained_bytes(tx: &WriteTx<'_>, retained_bytes: i64) -> Result<(), DatabaseError> {
    tx.execute(include_str!("update_storage_metadata.sql"), &[&retained_bytes])?;
    Ok(())
}
