//! Returns a note script by its root.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::note::NoteScript;

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_note_script_by_root.sql");

/// Returns the script for a note by its root.
pub(crate) fn select_note_script_by_root(
    tx: &ReadTx<'_>,
    root: Word,
) -> Result<Option<NoteScript>, DatabaseError> {
    // `script_root` is the primary key, so the statement returns zero or one row.
    Ok(tx.query(SQL, &[&root], |row| row.get::<NoteScript>(0))?.into_iter().next())
}
