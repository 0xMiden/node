//! Bounded target-pinned prefix discovery with partial-block cursors.
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNullifierPrefixLimit};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::DatabaseError;
use crate::db::NullifierInfo;
use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::state::ScopedBlockRange;

/// Inclusive block-and-nullifier position where the next page starts.
#[derive(Clone, Copy)]
pub struct NullifierCursor {
    pub(crate) block: BlockNumber,
    pub(crate) nullifier: Nullifier,
}
/// A bounded page of prefix-matching nullifier events.
pub struct NullifierUpdatesPage {
    pub records: Vec<NullifierInfo>,
    /// First omitted item, or `None` when the range is complete.
    pub next_cursor: Option<NullifierCursor>,
}

/// Prefix-matching nullifier events in block-and-nullifier order.
pub(crate) struct NullifierUpdatesPaged {
    prefixes: Vec<u16>,
    range: RangeInclusive<BlockNumber>,
    page_size: NonZeroUsize,
}

impl NullifierUpdatesPaged {
    pub(crate) fn new(
        prefixes: Vec<u16>,
        range: ScopedBlockRange,
        page_size: NonZeroUsize,
    ) -> Self {
        Self {
            prefixes,
            range: range.into_inner(),
            page_size,
        }
    }
}

impl Paginated for NullifierUpdatesPaged {
    type Item = NullifierInfo;
    type Cursor = Option<NullifierCursor>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Self::Cursor,
    ) -> Result<Page<Self::Item, Self::Cursor>, DatabaseError> {
        QueryParamNullifierPrefixLimit::check(self.prefixes.len())?;
        if self.range.is_empty() {
            return Err(DatabaseError::InvalidBlockRange {
                from: *self.range.start(),
                to: *self.range.end(),
            });
        }
        let prefixes = InList::from_values(&self.prefixes);
        let next = next.as_ref().filter(|next| next.block >= *self.range.start());
        let block = next.map_or(*self.range.start(), |next| next.block);
        let key = key_cursor(next.map(|next| &next.nullifier));
        let limit = i64::try_from(self.page_size.get().saturating_add(1))
            .expect("page size fits within i64");
        let rows = tx.query(
            include_str!("select_page.sql"),
            &[&prefixes, self.range.end(), &limit, &block, &key],
            |row| {
                Ok(NullifierInfo {
                    nullifier: row.get(0)?,
                    block_num: row.get(1)?,
                })
            },
        )?;
        Ok(Page::from_overflow(rows, self.page_size, |row| {
            Some(NullifierCursor {
                block: row.block_num,
                nullifier: row.nullifier,
            })
        }))
    }
}
