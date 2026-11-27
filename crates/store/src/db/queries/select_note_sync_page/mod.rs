//! Bounded note synchronization pages, including continuations within a block.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteTagLimit};
use miden_protocol::block::{BlockNoteIndex, BlockNumber};

use super::note_row::note_sync_record_from_row;
use crate::db::pagination::Page;
use crate::state::ScopedBlockRange;
use crate::{DatabaseError, NoteSyncRecord};

/// Inclusive note position where the next page starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteSyncCursor {
    pub(crate) block_num: BlockNumber,
    pub(crate) index: BlockNoteIndex,
}

/// A bounded page of matching note records.
pub struct NoteSyncPage {
    pub notes: Vec<NoteSyncRecord>,
    /// First omitted item, or `None` when the range is complete.
    pub next_cursor: Option<NoteSyncCursor>,
}

/// Matching note records in block, batch, and note-index order.
pub(crate) fn note_sync_page(
    tx: &ReadTx<'_>,
    tags: Vec<u32>,
    range: ScopedBlockRange,
    cursor: Option<NoteSyncCursor>,
    page_size: NonZeroUsize,
) -> Result<NoteSyncPage, DatabaseError> {
    let range = range.into_inner();
    QueryParamNoteTagLimit::check(tags.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    let tags = InList::from_values(tags);
    let next = cursor.filter(|next| next.block_num >= *range.start());
    let block = next.map_or(*range.start(), |next| next.block_num);
    let batch =
        next.map_or(0, |next| i64::try_from(next.index.batch_idx()).expect("batch index fits i64"));
    let index = next.map_or(0, |next| {
        i64::try_from(next.index.note_idx_in_batch()).expect("note index fits i64")
    });
    let limit =
        i64::try_from(page_size.get().saturating_add(1)).expect("page size fits within i64");
    let rows = tx.query(
        include_str!("select_page.sql"),
        &[&tags, range.end(), &block, &batch, &index, &limit],
        note_sync_record_from_row,
    )?;
    let page = Page::from_overflow(rows, page_size, |row| NoteSyncCursor {
        block_num: row.block_num,
        index: row.note_index,
    });
    Ok(NoteSyncPage {
        notes: page.items,
        next_cursor: page.next,
    })
}
