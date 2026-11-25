use miden_node_db::sqlite::InList;
use miden_protocol::note::NoteId;

use super::ReadTransaction;
use crate::db::NoteRecord;
use crate::db::queries::note_row::note_record_from_row;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the full records, with details and script, of the requested notes in this
    /// transaction's snapshot.
    ///
    /// Unknown note IDs are omitted from the result.
    pub fn select_notes_by_id(
        &self,
        note_ids: &[NoteId],
    ) -> Result<Vec<NoteRecord>, DatabaseError> {
        let note_ids = InList::from_values(note_ids);
        Ok(self.inner.query(SQL, &[&note_ids], note_record_from_row)?)
    }
}
