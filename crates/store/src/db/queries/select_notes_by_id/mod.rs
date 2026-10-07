//! Returns full note records, with details and script, for a set of note ids.

use miden_node_db::sqlite::{InList, ReadTx};
use miden_protocol::note::NoteId;

use crate::db::NoteRecord;
use crate::db::queries::note_row::note_record_from_row;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_notes_by_id.sql");

/// Select all notes matching the given set of identifiers.
pub(crate) fn select_notes_by_id(
    tx: &ReadTx<'_>,
    note_ids: &[NoteId],
) -> Result<Vec<NoteRecord>, DatabaseError> {
    let note_ids = InList::from_values(note_ids);

    Ok(tx.query(SQL, &[&note_ids], note_record_from_row)?)
}
