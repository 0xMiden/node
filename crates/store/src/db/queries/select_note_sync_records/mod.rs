//! Returns note sync records for a set of note ids.

use std::collections::BTreeMap;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
use miden_protocol::note::NoteId;

use crate::db::NoteSyncRecord;
use crate::db::queries::note_row::note_sync_record_from_row;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_note_sync_records.sql");

/// Select note sync records matching the given note IDs.
///
/// # Parameters
/// * `note_ids`: Slice of note IDs to query
///     - Limit: 0 <= count <= 1000
///
/// # Returns
///
/// - Empty map if no matching `note`.
/// - Otherwise, note sync records keyed by [`NoteId`].
pub(crate) fn select_note_sync_records(
    tx: &ReadTx<'_>,
    note_ids: &[NoteId],
) -> Result<BTreeMap<NoteId, NoteSyncRecord>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_ids.len())?;

    let note_ids = InList::from_values(note_ids);

    Ok(tx
        .query(SQL, &[&note_ids], note_sync_record_from_row)?
        .into_iter()
        .map(|note| (note.note_id, note))
        .collect())
}
