//! Bounded changed-account identities at a pinned target.
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

use super::check_account_history_target;
use crate::DatabaseError;

#[derive(Debug)]
pub struct AccountCommitmentChangesPage {
    pub changes: Vec<(AccountId, BlockNumber)>,
    pub next_cursor: Option<AccountId>,
}

pub(crate) fn select_account_commitment_changes(
    tx: &ReadTx<'_>,
    ids: &[AccountId],
    range: RangeInclusive<BlockNumber>,
    cursor: Option<AccountId>,
    page_size: NonZeroUsize,
) -> Result<AccountCommitmentChangesPage, DatabaseError> {
    QueryParamAccountIdLimit::check(ids.len())?;
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    check_account_history_target(tx, *range.end())?;
    let ids = InList::from_values(ids);
    let limit = page_size.get();
    let query_limit = i64::try_from(limit.saturating_add(1)).expect("page size fits i64");
    let map_row = |row: &miden_node_db::sqlite::Row<'_>| {
        Ok((row.get::<AccountId>(0)?, row.get::<BlockNumber>(1)?))
    };
    let mut changes = match cursor {
        None => tx.query(
            include_str!("select_page.sql"),
            &[&ids, range.start(), range.end(), &query_limit],
            map_row,
        )?,
        Some(cursor) => tx.query(
            include_str!("select_page_after.sql"),
            &[&ids, range.start(), range.end(), &cursor, &query_limit],
            map_row,
        )?,
    };
    let has_more = changes.len() > limit;
    changes.truncate(limit);
    let next_cursor = has_more.then(|| changes.last().expect("continued page is nonempty").0);
    Ok(AccountCommitmentChangesPage { changes, next_cursor })
}
