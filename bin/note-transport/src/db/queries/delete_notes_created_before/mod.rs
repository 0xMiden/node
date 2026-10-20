use miden_node_db::sqlite::WriteTx;

use crate::db::StorageError;

/// Deletes up to `limit` notes created before `cutoff` and returns their total payload size. The
/// oldest timestamps are selected first. The cursor orders equal timestamps.
pub fn delete_notes_created_before(
    tx: &WriteTx<'_>,
    cutoff: i64,
    limit: u32,
) -> Result<i64, StorageError> {
    let sizes =
        tx.query(include_str!("delete_notes_created_before.sql"), &[&cutoff, &limit], |row| {
            row.get::<i64>(0)
        })?;
    sizes
        .into_iter()
        .try_fold(0_i64, i64::checked_add)
        .ok_or_else(|| StorageError::InvalidData("removed byte count overflow".into()))
}
