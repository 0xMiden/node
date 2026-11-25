use std::collections::HashSet;

use miden_node_db::sqlite::InList;
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
use miden_protocol::note::NoteId;

use super::ReadTransaction;
use crate::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the requested note IDs present in this transaction's snapshot.
    pub fn select_existing_note_ids(
        &self,
        note_ids: &[NoteId],
    ) -> Result<HashSet<NoteId>, DatabaseError> {
        QueryParamNoteCommitmentLimit::check(note_ids.len())?;
        let note_ids = InList::from_values(note_ids);
        Ok(self
            .inner
            .query(SQL, &[&note_ids], |row| row.get::<NoteId>(0))?
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
mod tests;
