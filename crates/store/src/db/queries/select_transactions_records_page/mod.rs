//! Byte-budgeted pages of complete account transaction history.
use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_page::{MAX_PAGE_ROWS, load_page, summary_from_row};
use crate::db::pagination::key_cursor;
use crate::state::ScopedBlockRange;
use crate::{DatabaseError, TransactionRecord};

/// Inclusive block-and-transaction position where the next page starts.
#[derive(Clone, Copy)]
pub struct TransactionCursor {
    pub(crate) block: BlockNumber,
    pub(crate) id: TransactionId,
}

/// A bounded page of complete transaction history.
pub struct TransactionRecordsPage {
    pub records: Vec<TransactionRecord>,
    /// First omitted transaction, or `None` when the query is complete.
    pub next_cursor: Option<TransactionCursor>,
}

/// Byte-budgeted transaction records in database cursor order.
///
/// Metadata bounds the selected prefix before note contents and proofs are loaded. An oversized
/// first record is included so a nonempty query always makes progress.
pub(crate) fn transaction_records_page(
    tx: &ReadTx<'_>,
    ids: Vec<AccountId>,
    range: ScopedBlockRange,
    cursor: Option<TransactionCursor>,
    byte_limit: NonZeroUsize,
) -> Result<TransactionRecordsPage, DatabaseError> {
    let range = range.into_inner();
    QueryParamAccountIdLimit::check(ids.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    let ids = InList::from_values(ids);
    let next = cursor.as_ref().filter(|next| next.block >= *range.start());
    let block = next.map_or(*range.start(), |next| next.block);
    let key = key_cursor(next.map(|next| &next.id));
    let limit = i64::try_from(MAX_PAGE_ROWS + 1).expect("page size fits i64");
    let summaries = tx.query(
        include_str!("select_page.sql"),
        &[range.end(), &ids, &limit, &block, &key],
        summary_from_row,
    )?;
    let (mut records, next) = load_page(tx, summaries, byte_limit)?;
    records.sort_unstable_by_key(|record| (record.block_num, record.header.id().as_bytes()));
    Ok(TransactionRecordsPage {
        records,
        next_cursor: next.map(|row| TransactionCursor {
            block: row.block_num,
            id: row.transaction_id,
        }),
    })
}
