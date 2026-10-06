//! Loads the data for a note sync across every matching block in a range.

use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;

use crate::db::NoteSyncUpdate;
use crate::db::queries::{select_block_header_by_block_num, select_notes_since_block_by_tag};
use crate::errors::NoteSyncError;

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

/// Loads the data necessary for a note sync across all matching blocks in the given range.
///
/// Returns one [`NoteSyncUpdate`] per block that contains at least one note matching the
/// requested tags, ordered by block number ascending.
pub(crate) fn get_note_sync_multi(
    tx: &ReadTx<'_>,
    note_tags: &[u32],
    block_range: RangeInclusive<BlockNumber>,
    max_response_payload_bytes: usize,
) -> Result<Vec<NoteSyncUpdate>, NoteSyncError> {
    let mut current_from = *block_range.start();
    let block_end = *block_range.end();
    let mut updates = Vec::new();
    let mut accumulated_size = 0usize;

    loop {
        let notes = select_notes_since_block_by_tag(tx, note_tags, current_from..=block_end)?;

        let Some(block_num) = notes.first().map(|note| note.block_num) else {
            break;
        };

        accumulated_size += NOTE_SYNC_BLOCK_OVERHEAD_BYTES + notes.len() * NOTE_SYNC_RECORD_BYTES;

        if !updates.is_empty() && accumulated_size > max_response_payload_bytes {
            break;
        }

        let block_header = select_block_header_by_block_num(tx, Some(block_num))?
            .ok_or(NoteSyncError::EmptyBlockHeadersTable)?;
        updates.push(NoteSyncUpdate { notes, block_header });
        current_from = block_num + 1;
    }

    Ok(updates)
}
