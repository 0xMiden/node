use miden_node_db::sqlite::ReadTx;

use crate::db::StorageError;

/// Reads the retained payload size.
pub fn select_nonce(tx: &ReadTx<'_>) -> Result<u64, StorageError> {
    let nonce = tx
        .query(include_str!("select_nonce.sql"), &[], |row| row.get::<Vec<u8>>(0))?
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::InvalidData("storage metadata is missing".into()))?;

    nonce
        .try_into()
        .map_err(|_| StorageError::InvalidData("invalid database nonce length".into()))
        .map(u64::from_le_bytes)
}
