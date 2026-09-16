use miden_node_db::sqlite::ReadTx;

use crate::db::StorageError;

pub struct StorageMetadata {
    pub next_cursor: i64,
    pub retained_bytes: i64,
}

/// Reads the durable cursor counter and retained payload size.
pub fn select_storage_metadata(tx: &ReadTx<'_>) -> Result<StorageMetadata, StorageError> {
    tx.query(include_str!("select_storage_metadata.sql"), &[], |row| {
        Ok(StorageMetadata {
            next_cursor: row.get(0)?,
            retained_bytes: row.get(1)?,
        })
    })?
    .into_iter()
    .next()
    .ok_or_else(|| StorageError::InvalidData("storage metadata is missing".into()))
}
