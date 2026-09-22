use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::note::NoteId;

/// Returns whether the note ID is already stored.
pub fn note_exists(tx: &ReadTx<'_>, id: &NoteId) -> Result<bool, DatabaseError> {
    Ok(tx.query(include_str!("note_exists.sql"), &[id], |row| row.get::<bool>(0))?[0])
}
