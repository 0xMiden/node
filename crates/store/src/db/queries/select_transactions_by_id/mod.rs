//! Bounded transaction lookup at a fixed target.
use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamTransactionIdLimit};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_page::{MAX_PAGE_ROWS, load_page, summary_from_row};
use crate::{DatabaseError, TransactionRecord};

pub struct TransactionsByIdPage {
    pub records: Vec<TransactionRecord>,
    pub next_cursor: Option<TransactionId>,
}

/// Selects requested transactions committed by the target in database ID order.
///
/// Selects records by estimated byte size before loading their note contents. Reads
/// one extra metadata row to detect continuation, with at least one record per nonempty page.
pub(crate) fn select_transactions_by_id(
    tx: &ReadTx<'_>,
    ids: &[TransactionId],
    target: BlockNumber,
    cursor: Option<TransactionId>,
    byte_limit: NonZeroUsize,
) -> Result<TransactionsByIdPage, DatabaseError> {
    QueryParamTransactionIdLimit::check(ids.len())?;
    let ids = InList::from_values(ids);
    let query_limit = i64::try_from(MAX_PAGE_ROWS + 1).expect("page size fits i64");
    let summaries = match cursor {
        None => tx.query(
            include_str!("select_page.sql"),
            &[&ids, &target, &query_limit],
            summary_from_row,
        )?,
        Some(cursor) => tx.query(
            include_str!("select_page_after.sql"),
            &[&ids, &target, &cursor, &query_limit],
            summary_from_row,
        )?,
    };
    let (records, next) = load_page(tx, summaries, byte_limit)?;
    let next_cursor = next.map(|last| last.transaction_id);
    Ok(TransactionsByIdPage { records, next_cursor })
}
