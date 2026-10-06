//! Row-count pages of complete account transaction history.
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_record::{transaction_row_from_row, with_output_note_proofs};
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
/// The cursor permits partial-block pages. Reconstructs only the returned rows and
/// does not truncate a block to satisfy an aggregate response-size estimate.
pub(crate) fn select_transactions_records_page(
    tx: &ReadTx<'_>,
    ids: &[AccountId],
    range: RangeInclusive<BlockNumber>,
    cursor: Option<TransactionCursor>,
    page_size: NonZeroUsize,
) -> Result<TransactionRecordsPage, DatabaseError> {
    QueryParamAccountIdLimit::check(ids.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    let ids = InList::from_values(ids);
    let limit = page_size.get();
    let query_limit = i64::try_from(limit.saturating_add(1)).expect("page size fits i64");
    let mut rows = match cursor {
        None => tx.query(
            include_str!("select_page.sql"),
            &[range.start(), range.end(), &ids, &query_limit],
            transaction_row_from_row,
        )?,
        Some(cursor) => tx.query(
            include_str!("select_page_after.sql"),
            &[range.start(), range.end(), &ids, &query_limit, &cursor.block, &cursor.id],
            transaction_row_from_row,
        )?,
    };
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = has_more.then(|| {
        let last = rows.last().expect("continued page is nonempty");
        TransactionCursor {
            block: last.block_num,
            id: last.transaction_id,
        }
    });
    let records = with_output_note_proofs(tx, rows)?;
    Ok(TransactionRecordsPage { records, next_cursor })
}
