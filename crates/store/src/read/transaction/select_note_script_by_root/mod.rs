use miden_protocol::Word;
use miden_protocol::note::NoteScript;

use super::ReadTransaction;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the note script stored under `root`, or `None` if it is absent.
    pub fn select_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, DatabaseError> {
        // `script_root` is the primary key, so the statement returns zero or one row.
        Ok(self
            .inner
            .query(SQL, &[&root], |row| row.get::<NoteScript>(0))?
            .into_iter()
            .next())
    }
}
