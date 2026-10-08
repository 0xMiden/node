//! Bounded transaction lookup at a fixed target.
use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamTransactionIdLimit};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_record::{transaction_row_from_row, with_output_note_proofs};
use crate::{DatabaseError, TransactionRecord};

pub struct TransactionsByIdPage {
    pub records: Vec<TransactionRecord>,
    pub next_cursor: Option<TransactionId>,
}

/// Selects requested transactions committed by the target in database ID order.
///
/// Reconstructs complete records only for the returned page. Reads one extra row to
/// detect continuation without using aggregate byte estimates.
pub(crate) fn select_transactions_by_id(
    tx: &ReadTx<'_>,
    ids: &[TransactionId],
    target: BlockNumber,
    cursor: Option<TransactionId>,
    page_size: NonZeroUsize,
) -> Result<TransactionsByIdPage, DatabaseError> {
    QueryParamTransactionIdLimit::check(ids.len())?;
    let ids = InList::from_values(ids);
    let limit = page_size.get();
    let query_limit = i64::try_from(limit.saturating_add(1)).expect("page size fits i64");
    let mut rows = match cursor {
        None => tx.query(
            include_str!("select_page.sql"),
            &[&ids, &target, &query_limit],
            transaction_row_from_row,
        )?,
        Some(cursor) => tx.query(
            include_str!("select_page_after.sql"),
            &[&ids, &target, &cursor, &query_limit],
            transaction_row_from_row,
        )?,
    };
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor =
        has_more.then(|| rows.last().expect("continued page is nonempty").transaction_id);
    let records = with_output_note_proofs(tx, rows)?;
    Ok(TransactionsByIdPage { records, next_cursor })
}
