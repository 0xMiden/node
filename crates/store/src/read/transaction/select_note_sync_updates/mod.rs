use std::ops::RangeInclusive;

use miden_protocol::block::BlockNumber;

use super::ReadTransaction;
use crate::db::NoteSyncUpdate;
use crate::db::pagination::Page;
use crate::db::queries::select_notes_since_block_by_tag;
use crate::errors::DatabaseError;

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

impl ReadTransaction<'_> {
    /// Returns the page of note sync data within `block_range`: one [`NoteSyncUpdate`] for each
    /// block with at least one note matching `note_tags`, ordered by block number.
    ///
    /// The page starts at the beginning of `block_range` and holds as many blocks as fit within
    /// `max_response_payload_bytes`, counting the MMR proof each block needs in the response. It
    /// always holds at least one block, even when that block alone exceeds the limit, so that
    /// pagination keeps moving.
    pub fn select_note_sync_updates(
        &self,
        note_tags: &[u32],
        block_range: RangeInclusive<BlockNumber>,
        max_response_payload_bytes: usize,
    ) -> Result<Page<NoteSyncUpdate, BlockNumber>, DatabaseError> {
        let (mut current_from, block_end) = block_range.into_inner();
        let mut updates: Vec<NoteSyncUpdate> = Vec::new();
        let mut accumulated_size = 0usize;

        loop {
            let notes =
                select_notes_since_block_by_tag(self.inner, note_tags, current_from..=block_end)?;

            let Some(block_num) = notes.first().map(|note| note.block_num) else {
                // No more matching notes exist in the range.
                return Ok(Page { items: updates, next: None });
            };

            accumulated_size +=
                NOTE_SYNC_BLOCK_OVERHEAD_BYTES + notes.len() * NOTE_SYNC_RECORD_BYTES;

            if let Some(last_update) = updates.last()
                && accumulated_size > max_response_payload_bytes
            {
                let next = last_update.block_header.block_num().child();
                return Ok(Page { items: updates, next: Some(next) });
            }

            let block_header = self.select_block_header(block_num)?.ok_or_else(|| {
                DatabaseError::DataCorrupted(format!("block {block_num} has notes but no header"))
            })?;
            updates.push(NoteSyncUpdate { notes, block_header });
            current_from = block_num + 1;
        }
    }
}
