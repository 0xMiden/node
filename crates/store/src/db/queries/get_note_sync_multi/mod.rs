//! Loads the data for a note sync across every matching block in a range.

use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;

use crate::db::NoteSyncUpdate;
use crate::db::pagination::{Page, Paginated};
use crate::db::queries::{select_block_header_by_block_num, select_notes_since_block_by_tag};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockRange;

/// Estimated byte size of a [`NoteSyncUpdate`] excluding its notes.
///
/// Includes a canonical header with validator keys, a scheduled protocol configuration, and an
/// MMR proof with 32 siblings.
pub(crate) const NOTE_SYNC_BLOCK_OVERHEAD_BYTES: usize = 1800;

/// Estimated byte size of a single [`NoteSyncRecord`](crate::db::NoteSyncRecord).
///
/// Includes a note ID, an index, compact metadata with four attachment entries, and a sparse
/// Merkle path with 16 siblings.
pub(crate) const NOTE_SYNC_RECORD_BYTES: usize = 900;

/// Paginated query over note sync data within an inclusive block range: one [`NoteSyncUpdate`] for
/// each block with at least one note matching the requested tags, ordered by block number.
///
/// A page holds as many blocks as fit within `max_response_payload_bytes`. It always holds at least
/// one block, even when that block alone exceeds the limit, so that pagination keeps moving.
#[derive(Debug, Clone)]
pub(crate) struct NoteSyncMulti {
    note_tags: Vec<u32>,
    block_range: RangeInclusive<BlockNumber>,
    max_response_payload_bytes: usize,
}

impl NoteSyncMulti {
    /// Creates the query for `note_tags` within `block_range`, with pages limited to
    /// `max_response_payload_bytes`.
    pub(crate) fn new(
        note_tags: Vec<u32>,
        block_range: ScopedBlockRange,
        max_response_payload_bytes: usize,
    ) -> Self {
        Self {
            note_tags,
            block_range: block_range.into_inner(),
            max_response_payload_bytes,
        }
    }
}

impl Paginated for NoteSyncMulti {
    type Item = NoteSyncUpdate;
    type Cursor = BlockNumber;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        after: Option<&BlockNumber>,
    ) -> Result<Page<NoteSyncUpdate, BlockNumber>, DatabaseError> {
        let block_from = after.map_or(*self.block_range.start(), |block| block.child());
        get_note_sync_multi(
            tx,
            &self.note_tags,
            block_from..=*self.block_range.end(),
            self.max_response_payload_bytes,
        )
    }
}

/// Loads the page of note sync data that starts at the beginning of `block_range`.
fn get_note_sync_multi(
    tx: &ReadTx<'_>,
    note_tags: &[u32],
    block_range: RangeInclusive<BlockNumber>,
    max_response_payload_bytes: usize,
) -> Result<Page<NoteSyncUpdate, BlockNumber>, DatabaseError> {
    let mut current_from = *block_range.start();
    let block_end = *block_range.end();
    let mut updates: Vec<NoteSyncUpdate> = Vec::new();
    let mut accumulated_size = 0usize;

    loop {
        let notes = select_notes_since_block_by_tag(tx, note_tags, current_from..=block_end)?;

        let Some(block_num) = notes.first().map(|note| note.block_num) else {
            // No more matching notes exist in the range.
            return Ok(Page { items: updates, next: None });
        };

        accumulated_size += NOTE_SYNC_BLOCK_OVERHEAD_BYTES + notes.len() * NOTE_SYNC_RECORD_BYTES;

        if let Some(last_update) = updates.last()
            && accumulated_size > max_response_payload_bytes
        {
            let next = last_update.block_header.block_num();
            return Ok(Page { items: updates, next: Some(next) });
        }

        let block_header =
            select_block_header_by_block_num(tx, Some(block_num))?.ok_or_else(|| {
                DatabaseError::DataCorrupted(format!("block {block_num} has notes but no header"))
            })?;
        updates.push(NoteSyncUpdate { notes, block_header });
        current_from = block_num + 1;
    }
}
