use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

use crate::db::{NewNote, StorageError};

/// Inserts a note with the assigned timestamp. SQLite assigns the sequence.
pub fn insert_note(tx: &WriteTx<'_>, note: &NewNote, created_at: i64) -> Result<(), StorageError> {
    tx.execute(
        include_str!("insert_note.sql"),
        &[
            &note.header.id(),
            &note.header.metadata().tag(),
            &note.header,
            &note.details,
            &created_at,
            &note.after_block_num,
        ],
    )
    .map_err(|error| match error {
        DatabaseError::Rusqlite(rusqlite::Error::SqliteFailure(code, _))
            if code.code == rusqlite::ErrorCode::DiskFull =>
        {
            StorageError::Capacity("database full or cursor exhausted".into())
        },
        error => StorageError::Database(error),
    })?;
    Ok(())
}
