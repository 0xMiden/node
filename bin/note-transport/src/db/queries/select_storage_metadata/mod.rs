use miden_node_db::sqlite::ReadTx;

use crate::db::StorageError;

pub struct StorageMetadata {
    pub next_cursor: i64,
    pub retained_bytes: i64,
    pub nonce: u64,
}

/// Reads the durable cursor counter, retained payload size, and database nonce.
pub fn select_storage_metadata(tx: &ReadTx<'_>) -> Result<StorageMetadata, StorageError> {
    let (next_cursor, retained_bytes, nonce) = tx
        .query(include_str!("select_storage_metadata.sql"), &[], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get::<Vec<u8>>(2)?))
        })?
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::InvalidData("storage metadata is missing".into()))?;
    let nonce = nonce
        .try_into()
        .map_err(|_| StorageError::InvalidData("invalid database nonce length".into()))?;
    Ok(StorageMetadata {
        next_cursor,
        retained_bytes,
        nonce: u64::from_le_bytes(nonce),
    })
}
