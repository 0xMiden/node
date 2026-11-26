//! Bounded target-pinned prefix discovery with partial-block cursors.
use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNullifierPrefixLimit};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::DatabaseError;
use crate::db::NullifierInfo;
use crate::db::pagination::{Page, key_cursor};
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
pub(crate) fn nullifier_updates_page(
    tx: &ReadTx<'_>,
    prefixes: Vec<u16>,
    range: ScopedBlockRange,
    cursor: Option<NullifierCursor>,
    page_size: NonZeroUsize,
) -> Result<NullifierUpdatesPage, DatabaseError> {
    let range = range.into_inner();
    QueryParamNullifierPrefixLimit::check(prefixes.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    let prefixes = InList::from_values(prefixes);
    let next = cursor.as_ref().filter(|next| next.block >= *range.start());
    let block = next.map_or(*range.start(), |next| next.block);
    let key = key_cursor(next.map(|next| &next.nullifier));
    let limit =
        i64::try_from(page_size.get().saturating_add(1)).expect("page size fits within i64");
    let rows = tx.query(
        include_str!("select_page.sql"),
        &[&prefixes, range.end(), &limit, &block, &key],
        |row| {
            Ok(NullifierInfo {
                nullifier: row.get(0)?,
                block_num: row.get(1)?,
            })
        },
    )?;
    let page = Page::from_overflow(rows, page_size, |row| NullifierCursor {
        block: row.block_num,
        nullifier: row.nullifier,
    });
    Ok(NullifierUpdatesPage {
        records: page.items,
        next_cursor: page.next,
    })
}
