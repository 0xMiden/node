//! Bounded transaction lookup at a fixed target.
use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamTransactionIdLimit};
use miden_protocol::transaction::TransactionId;

use super::transaction_page::{MAX_PAGE_ROWS, load_page, summary_from_row};
use crate::db::pagination::key_cursor;
use crate::state::ScopedBlockNum;
use crate::{DatabaseError, TransactionRecord};

/// A bounded page of requested transactions committed by the target.
pub struct TransactionsByIdPage {
    pub records: Vec<TransactionRecord>,
    /// First omitted transaction, or `None` when the query is complete.
    pub next_cursor: Option<TransactionId>,
}

/// Byte-budgeted transaction records in database cursor order.
///
/// Metadata bounds the selected prefix before note contents and proofs are loaded. An oversized
/// first record is included so a nonempty query always makes progress.
pub(crate) fn transactions_by_id_page(
    tx: &ReadTx<'_>,
    ids: Vec<TransactionId>,
    target: ScopedBlockNum,
    cursor: Option<TransactionId>,
    byte_limit: NonZeroUsize,
) -> Result<TransactionsByIdPage, DatabaseError> {
    QueryParamTransactionIdLimit::check(ids.len())?;
    let ids = InList::from_values(ids);
    let key = key_cursor(cursor.as_ref());
    let limit = i64::try_from(MAX_PAGE_ROWS + 1).expect("page size fits i64");
    let summaries = tx.query(
        include_str!("select_page.sql"),
        &[&ids, &*target, &key, &limit],
        summary_from_row,
    )?;
    let (records, next) = load_page(tx, summaries, byte_limit)?;
    Ok(TransactionsByIdPage {
        records,
        next_cursor: next.map(|row| row.transaction_id),
    })
}
