//! Returns the persisted status of a note by its note ID.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::note::NoteId;

use crate::db::queries::{NoteSponsorshipRow, select_note_sponsorships};

const SQL: &str = include_str!("get_note_status.sql");

/// Row returned by [`get_note_status`].
#[derive(Debug, Clone)]
pub struct NoteStatusRow {
    pub last_error: Option<String>,
    pub attempt_count: i64,
    pub last_attempt: Option<i64>,
    pub committed_at: Option<i64>,
    /// `FEE_SPONSORSHIP` notes bound to the note.
    pub sponsorships: Vec<NoteSponsorshipRow>,
}

/// Returns the status for a note identified by its note ID, together with the `FEE_SPONSORSHIP`
/// notes bound to it.
pub fn get_note_status(
    tx: &ReadTx<'_>,
    note_id: NoteId,
) -> Result<Option<NoteStatusRow>, DatabaseError> {
    let Some(mut status) = tx
        .query(SQL, &[&note_id], |row| {
            Ok(NoteStatusRow {
                last_error: row.get::<Option<String>>(0)?,
                attempt_count: row.get::<i64>(1)?,
                last_attempt: row.get::<Option<i64>>(2)?,
                committed_at: row.get::<Option<i64>>(3)?,
                sponsorships: Vec::new(),
            })
        })?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };

    status.sponsorships = select_note_sponsorships(tx, note_id)?;
    Ok(Some(status))
}
