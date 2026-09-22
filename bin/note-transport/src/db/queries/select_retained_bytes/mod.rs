use miden_node_db::sqlite::ReadTx;

use crate::db::StorageError;

/// Reads the retained payload size.
pub fn select_retained_bytes(tx: &ReadTx<'_>) -> Result<i64, StorageError> {
    tx.query(include_str!("select_retained_bytes.sql"), &[], |row| row.get::<i64>(0))?
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::InvalidData("storage metadata is missing".into()))
}
