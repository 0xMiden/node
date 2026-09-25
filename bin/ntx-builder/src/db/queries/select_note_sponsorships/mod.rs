//! Selects the `FEE_SPONSORSHIP` notes bound to a feature note.

use miden_node_db::sqlite::ReadTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};

use crate::sponsorship::SponsorshipNote;

const SQL: &str = include_str!("select_note_sponsorships.sql");

/// Row returned by [`select_note_sponsorships`].
#[derive(Debug, Clone)]
pub struct NoteSponsorshipRow {
    pub note: SponsorshipNote,
    pub committed_at: Option<BlockNumber>,
    pub last_attempt: Option<BlockNumber>,
    pub last_error: Option<String>,
}

/// Returns every `FEE_SPONSORSHIP` note bound to the given feature note, consumed or not, ordered
/// by sponsorship note ID.
pub fn select_note_sponsorships(
    tx: &ReadTx<'_>,
    feature_note_id: NoteId,
) -> Result<Vec<NoteSponsorshipRow>, DatabaseError> {
    tx.query(SQL, &[&feature_note_id], |row| {
        let note = SponsorshipNote::try_from(row.get::<Note>(0)?).map_err(|source| {
            DatabaseError::deserialization("failed to convert to sponsorship note", source)
        })?;
        let committed_at = row.get::<Option<i64>>(1)?.map(BlockNumber::from_raw_sql).transpose()?;
        let last_attempt = row.get::<Option<i64>>(2)?.map(BlockNumber::from_raw_sql).transpose()?;
        let last_error = row.get::<Option<String>>(3)?;
        Ok(NoteSponsorshipRow {
            note,
            committed_at,
            last_attempt,
            last_error,
        })
    })
}
