//! Returns the notes that match a set of tags, from the first block in the range that has any.

use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteTagLimit};
use miden_protocol::block::BlockNumber;

use crate::db::NoteSyncRecord;
use crate::db::queries::note_row::note_sync_record_from_row;
use crate::errors::DatabaseError;

const SQL_FIRST_BLOCK: &str = include_str!("select_first_block_with_tags.sql");
const SQL_NOTES_IN_BLOCK: &str = include_str!("select_notes_in_block_by_tag.sql");

/// Select notes matching the given tags within a block range.
///
/// # Parameters
/// * `note_tags`: List of note tags to filter by
///     - Limit: 0 <= count <= 1000
/// * `block_range`: Range of blocks to search (inclusive)
///
/// # Returns
///
/// All matching notes from the first block within the range containing a matching note. If no
/// matching notes are found at all, then an empty vector is returned.
pub(crate) fn select_notes_since_block_by_tag(
    tx: &ReadTx<'_>,
    note_tags: &[u32],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<Vec<NoteSyncRecord>, DatabaseError> {
    QueryParamNoteTagLimit::check(note_tags.len())?;

    let tags = InList::from_values(note_tags);
    let first_block = tx
        .query(SQL_FIRST_BLOCK, &[&tags, block_range.start(), block_range.end()], |row| {
            row.get::<BlockNumber>(0)
        })?
        .into_iter()
        .next();

    let Some(first_block) = first_block else {
        return Ok(Vec::new());
    };

    Ok(tx.query(SQL_NOTES_IN_BLOCK, &[&tags, &first_block], note_sync_record_from_row)?)
}
