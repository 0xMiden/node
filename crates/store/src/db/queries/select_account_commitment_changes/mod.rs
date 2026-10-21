//! Bounded changed-account identities at a pinned target.
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

use super::check_account_history_target;
use crate::DatabaseError;
use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::state::ScopedBlockRange;

/// A bounded page of changed account identities at a pinned target.
#[derive(Debug)]
pub struct AccountCommitmentChangesPage {
    pub changes: Vec<(AccountId, BlockNumber)>,
    /// First omitted item, or `None` when the range is complete.
    pub next_cursor: Option<AccountId>,
}

/// Target-valid changed accounts in account-ID order.
pub(crate) struct AccountCommitmentChanges {
    ids: Vec<AccountId>,
    range: RangeInclusive<BlockNumber>,
    page_size: NonZeroUsize,
}

impl AccountCommitmentChanges {
    pub(crate) fn new(
        ids: Vec<AccountId>,
        range: ScopedBlockRange,
        page_size: NonZeroUsize,
    ) -> Self {
        Self {
            ids,
            range: range.into_inner(),
            page_size,
        }
    }
}

impl Paginated for AccountCommitmentChanges {
    type Item = (AccountId, BlockNumber);
    type Cursor = Option<AccountId>;

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
        check_account_history_target(tx, *self.range.end())?;
        let ids = InList::from_values(&self.ids);
        let key = key_cursor(next.as_ref());
        let limit = i64::try_from(self.page_size.get().saturating_add(1))
            .expect("page size fits within i64");
        let rows = tx.query(
            include_str!("select_page.sql"),
            &[&ids, self.range.start(), self.range.end(), &key, &limit],
            |row| Ok((row.get::<AccountId>(0)?, row.get::<BlockNumber>(1)?)),
        )?;
        Ok(Page::from_overflow(rows, self.page_size, |row| Some(row.0)))
    }
}
