//! Inserts the note scripts held by a block's notes.

use miden_node_db::sqlite::WriteTx;
use miden_node_tracing::miden_instrument;
use miden_protocol::Word;

use crate::COMPONENT;
use crate::db::NoteRecord;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("insert_note_script.sql");

/// Inserts the scripts held by the given notes. Notes without details (private notes) carry no
/// script, and a script root already in the table is left untouched.
///
/// # Returns
///
/// The number of affected rows.
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub(crate) fn insert_note_scripts<'a>(
    tx: &WriteTx<'_>,
    notes: impl IntoIterator<Item = &'a NoteRecord>,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    for note in notes {
        let Some(details) = note.details.as_ref() else {
            continue;
        };
        let script = details.script();
        // The column stores the root as its word representation.
        let script_root = Word::from(script.root());
        count += tx.execute(SQL, &[&script_root, script])?;
    }
    Ok(count)
}
