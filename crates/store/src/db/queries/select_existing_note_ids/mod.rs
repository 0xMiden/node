//! Returns which of the given note ids are stored.

use std::collections::HashSet;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteId;

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_existing_note_ids.sql");

/// Select the requested note IDs that the notes table contains at or before `up_to_block`.
pub(crate) fn select_existing_note_ids(
    tx: &ReadTx<'_>,
    note_ids: &[NoteId],
    up_to_block: BlockNumber,
) -> Result<HashSet<NoteId>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_ids.len())?;

    let note_ids = InList::from_values(note_ids);

    Ok(tx
        .query(SQL, &[&note_ids, &up_to_block], |row| row.get::<NoteId>(0))?
        .into_iter()
        .collect())
}
