//! Byte-budgeted pages of complete account transaction history.
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_page::{MAX_PAGE_ROWS, load_page, summary_from_row};
use crate::db::pagination::{Page, Paginated, key_cursor};
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
pub(crate) struct TransactionRecordsPaged {
    ids: Vec<AccountId>,
    range: RangeInclusive<BlockNumber>,
    byte_limit: NonZeroUsize,
}

impl TransactionRecordsPaged {
    pub(crate) fn new(
        ids: Vec<AccountId>,
        range: ScopedBlockRange,
        byte_limit: NonZeroUsize,
    ) -> Self {
        Self {
            ids,
            range: range.into_inner(),
            byte_limit,
        }
    }
}

impl Paginated for TransactionRecordsPaged {
    type Item = TransactionRecord;
    type Cursor = Option<TransactionCursor>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Self::Cursor,
    ) -> Result<Page<Self::Item, Self::Cursor>, DatabaseError> {
        QueryParamAccountIdLimit::check(self.ids.len())?;
        if self.range.is_empty() {
            return Err(DatabaseError::InvalidBlockRange {
                from: *self.range.start(),
                to: *self.range.end(),
            });
        }
        let ids = InList::from_values(&self.ids);
        let next = next.as_ref().filter(|next| next.block >= *self.range.start());
        let block = next.map_or(*self.range.start(), |next| next.block);
        let key = key_cursor(next.map(|next| &next.id));
        let limit = i64::try_from(MAX_PAGE_ROWS + 1).expect("page size fits i64");
        let summaries = tx.query(
            include_str!("select_page.sql"),
            &[self.range.end(), &ids, &limit, &block, &key],
            summary_from_row,
        )?;
        let (mut items, next) = load_page(tx, summaries, self.byte_limit)?;
        items.sort_unstable_by_key(|record| (record.block_num, record.header.id().as_bytes()));
        Ok(Page {
            items,
            next: next.map(|row| {
                Some(TransactionCursor {
                    block: row.block_num,
                    id: row.transaction_id,
                })
            }),
        })
    }
}
