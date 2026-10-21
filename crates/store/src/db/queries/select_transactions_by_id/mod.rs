//! Bounded transaction lookup at a fixed target.
use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamTransactionIdLimit};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_page::{MAX_PAGE_ROWS, load_page, summary_from_row};
use crate::db::pagination::{Page, Paginated, key_cursor};
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
pub(crate) struct TransactionsById {
    ids: Vec<TransactionId>,
    target: BlockNumber,
    byte_limit: NonZeroUsize,
}

impl TransactionsById {
    pub(crate) fn new(
        ids: Vec<TransactionId>,
        target: ScopedBlockNum,
        byte_limit: NonZeroUsize,
    ) -> Self {
        Self { ids, target: *target, byte_limit }
    }
}

impl Paginated for TransactionsById {
    type Item = TransactionRecord;
    type Cursor = Option<TransactionId>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Self::Cursor,
    ) -> Result<Page<Self::Item, Self::Cursor>, DatabaseError> {
        QueryParamTransactionIdLimit::check(self.ids.len())?;
        let ids = InList::from_values(&self.ids);
        let key = key_cursor(next.as_ref());
        let limit = i64::try_from(MAX_PAGE_ROWS + 1).expect("page size fits i64");
        let summaries = tx.query(
            include_str!("select_page.sql"),
            &[&ids, &self.target, &key, &limit],
            summary_from_row,
        )?;
        let (items, next) = load_page(tx, summaries, self.byte_limit)?;
        Ok(Page {
            items,
            next: next.map(|row| Some(row.transaction_id)),
        })
    }
}
