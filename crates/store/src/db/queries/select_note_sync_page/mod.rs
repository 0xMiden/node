//! Bounded note synchronization pages, including continuations within a block.

use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteTagLimit};
use miden_protocol::block::{BlockNoteIndex, BlockNumber};

use super::note_row::note_sync_record_from_row;
use crate::db::pagination::{Page, Paginated};
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
pub(crate) struct NoteSyncPaged {
    tags: Vec<u32>,
    range: RangeInclusive<BlockNumber>,
    page_size: NonZeroUsize,
}

impl NoteSyncPaged {
    pub(crate) fn new(tags: Vec<u32>, range: ScopedBlockRange, page_size: NonZeroUsize) -> Self {
        Self {
            tags,
            range: range.into_inner(),
            page_size,
        }
    }
}

impl Paginated for NoteSyncPaged {
    type Item = NoteSyncRecord;
    type Cursor = Option<NoteSyncCursor>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Self::Cursor,
    ) -> Result<Page<Self::Item, Self::Cursor>, DatabaseError> {
        QueryParamNoteTagLimit::check(self.tags.len())?;
        if self.range.is_empty() {
            return Err(DatabaseError::InvalidBlockRange {
                from: *self.range.start(),
                to: *self.range.end(),
            });
        }
        let tags = InList::from_values(&self.tags);
        let next = next.as_ref().filter(|next| next.block_num >= *self.range.start());
        let block = next.map_or(*self.range.start(), |next| next.block_num);
        let batch = next
            .map_or(0, |next| i64::try_from(next.index.batch_idx()).expect("batch index fits i64"));
        let index = next.map_or(0, |next| {
            i64::try_from(next.index.note_idx_in_batch()).expect("note index fits i64")
        });
        let limit = i64::try_from(self.page_size.get().saturating_add(1))
            .expect("page size fits within i64");
        let rows = tx.query(
            include_str!("select_page.sql"),
            &[&tags, self.range.end(), &block, &batch, &index, &limit],
            note_sync_record_from_row,
        )?;
        Ok(Page::from_overflow(rows, self.page_size, |row| {
            Some(NoteSyncCursor {
                block_num: row.block_num,
                index: row.note_index,
            })
        }))
    }
}
