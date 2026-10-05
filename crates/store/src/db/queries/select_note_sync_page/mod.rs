//! Bounded note synchronization pages, including continuations within a block.

use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteTagLimit};
use miden_protocol::block::{BlockNoteIndex, BlockNumber};

use super::note_row::note_sync_record_from_row;
use crate::{DatabaseError, NoteSyncRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteSyncCursor {
    pub(crate) block_num: BlockNumber,
    pub(crate) index: BlockNoteIndex,
}

pub struct NoteSyncPage {
    pub notes: Vec<NoteSyncRecord>,
    pub next_cursor: Option<NoteSyncCursor>,
}

pub(crate) fn select_note_sync_page(
    tx: &ReadTx<'_>,
    tags: &[u32],
    range: RangeInclusive<BlockNumber>,
    cursor: Option<NoteSyncCursor>,
    page_size: NonZeroUsize,
) -> Result<NoteSyncPage, DatabaseError> {
    QueryParamNoteTagLimit::check(tags.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    let tags = InList::from_values(tags);
    let limit = page_size.get();
    let query_limit = i64::try_from(limit.saturating_add(1)).expect("page size fits within i64");
    let mut notes = match cursor {
        None => tx.query(
            include_str!("select_page.sql"),
            &[&tags, range.start(), range.end(), &query_limit],
            note_sync_record_from_row,
        )?,
        Some(cursor) => {
            let batch_index =
                i64::try_from(cursor.index.batch_idx()).expect("batch index fits i64");
            let note_index =
                i64::try_from(cursor.index.note_idx_in_batch()).expect("note index fits i64");
            tx.query(
                include_str!("select_page_after.sql"),
                &[
                    &tags,
                    range.start(),
                    range.end(),
                    &cursor.block_num,
                    &batch_index,
                    &note_index,
                    &query_limit,
                ],
                note_sync_record_from_row,
            )?
        },
    };
    let has_more = notes.len() > limit;
    notes.truncate(limit);
    let next_cursor = has_more.then(|| {
        let last = notes.last().expect("continued page is nonempty");
        NoteSyncCursor {
            block_num: last.block_num,
            index: last.note_index,
        }
    });
    Ok(NoteSyncPage { notes, next_cursor })
}
