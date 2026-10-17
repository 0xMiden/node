//! Maps nullifiers to the ids of the notes that they consume.

use std::collections::BTreeMap;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_protocol::note::{NoteId, Nullifier};

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_note_ids_by_nullifier.sql");

/// Maps each given nullifier to its note ID.
///
/// Only public notes have a nullifier stored (`notes.nullifier` is NULL for private notes), so
/// private notes never match and are absent from the result.
pub(crate) fn select_note_ids_by_nullifier(
    tx: &ReadTx<'_>,
    nullifiers: &[Nullifier],
) -> Result<BTreeMap<Nullifier, NoteId>, DatabaseError> {
    if nullifiers.is_empty() {
        return Ok(BTreeMap::new());
    }

    let nullifiers = InList::from_values(nullifiers);

    let pairs = tx.query(SQL, &[&nullifiers], |row| {
        Ok((row.get::<Option<Nullifier>>(0)?, row.get::<NoteId>(1)?))
    })?;

    Ok(pairs
        .into_iter()
        .filter_map(|(nullifier, note_id)| nullifier.map(|nullifier| (nullifier, note_id)))
        .collect())
}
