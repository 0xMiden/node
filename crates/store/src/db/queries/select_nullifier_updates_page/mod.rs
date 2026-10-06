//! Bounded target-pinned prefix discovery with partial-block cursors.
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNullifierPrefixLimit};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::DatabaseError;
use crate::db::NullifierInfo;

#[derive(Clone, Copy)]
pub struct NullifierCursor {
    pub(crate) block: BlockNumber,
    pub(crate) nullifier: Nullifier,
}
pub struct NullifierUpdatesPage {
    pub records: Vec<NullifierInfo>,
    pub next_cursor: Option<NullifierCursor>,
}
/// Selects every prefix-matching consumption in the inclusive range without squashing.
///
/// The block-and-nullifier cursor follows database order and can split one block across pages.
pub(crate) fn select_nullifier_updates_page(
    tx: &ReadTx<'_>,
    prefixes: &[u16],
    range: RangeInclusive<BlockNumber>,
    cursor: Option<NullifierCursor>,
    page_size: NonZeroUsize,
) -> Result<NullifierUpdatesPage, DatabaseError> {
    QueryParamNullifierPrefixLimit::check(prefixes.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    let prefixes = InList::from_values(prefixes);
    let limit = page_size.get();
    let query_limit = i64::try_from(limit.saturating_add(1)).expect("page size fits i64");
    let decode = |row: &miden_node_db::sqlite::Row<'_>| {
        Ok(NullifierInfo {
            nullifier: row.get(0)?,
            block_num: row.get(1)?,
        })
    };
    let mut records = match cursor {
        None => tx.query(
            include_str!("select_page.sql"),
            &[&prefixes, range.start(), range.end(), &query_limit],
            decode,
        )?,
        Some(cursor) => tx.query(
            include_str!("select_page_after.sql"),
            &[
                &prefixes,
                range.start(),
                range.end(),
                &query_limit,
                &cursor.block,
                &cursor.nullifier,
            ],
            decode,
        )?,
    };
    let has_more = records.len() > limit;
    records.truncate(limit);
    let next_cursor = has_more.then(|| {
        let last = records.last().expect("continued page is nonempty");
        NullifierCursor {
            block: last.block_num,
            nullifier: last.nullifier,
        }
    });
    Ok(NullifierUpdatesPage { records, next_cursor })
}
