use miden_node_db::sqlite::ReadTx;

use crate::db::StorageError;

/// Reads the highest committed note sequence, including notes removed by retention.
pub fn select_head(tx: &ReadTx<'_>) -> Result<u64, StorageError> {
    let head = tx
        .query(include_str!("select_head.sql"), &[], |row| row.get::<i64>(0))?
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::InvalidData("note sequence watermark is missing".into()))?;
    u64::try_from(head)
        .map_err(|_| StorageError::InvalidData("invalid note sequence watermark".into()))
}
