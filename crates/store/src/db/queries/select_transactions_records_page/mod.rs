//! Byte-budgeted pages of complete account transaction history.
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_page::{MAX_PAGE_ROWS, load_page, summary_from_row};
use crate::{DatabaseError, TransactionRecord};

#[derive(Clone, Copy)]
pub struct TransactionCursor {
    pub(crate) block: BlockNumber,
    pub(crate) id: TransactionId,
}

pub struct TransactionRecordsPage {
    pub records: Vec<TransactionRecord>,
    pub next_cursor: Option<TransactionCursor>,
}

/// Selects complete account transaction events in block-and-ID database order.
///
/// The cursor permits partial-block pages. Selects records by estimated byte size before
/// loading their note contents, with at least one record per nonempty page.
pub(crate) fn select_transactions_records_page(
    tx: &ReadTx<'_>,
    ids: &[AccountId],
    range: RangeInclusive<BlockNumber>,
    cursor: Option<TransactionCursor>,
    byte_limit: NonZeroUsize,
) -> Result<TransactionRecordsPage, DatabaseError> {
    QueryParamAccountIdLimit::check(ids.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    let ids = InList::from_values(ids);
    let query_limit = i64::try_from(MAX_PAGE_ROWS + 1).expect("page size fits i64");
    // The cursor supplies the SQL lower bound. Use the first page if it precedes the range.
    let summaries = match cursor.filter(|cursor| cursor.block >= *range.start()) {
        None => tx.query(
            include_str!("select_page.sql"),
            &[range.start(), range.end(), &ids, &query_limit],
            summary_from_row,
        )?,
        Some(cursor) => tx.query(
            include_str!("select_page_after.sql"),
            &[range.end(), &ids, &query_limit, &cursor.block, &cursor.id],
            summary_from_row,
        )?,
    };
    let (mut records, next) = load_page(tx, summaries, byte_limit)?;
    records.sort_unstable_by_key(|record| (record.block_num, record.header.id().as_bytes()));
    let next_cursor = next.map(|last| TransactionCursor {
        block: last.block_num,
        id: last.transaction_id,
    });
    Ok(TransactionRecordsPage { records, next_cursor })
}
