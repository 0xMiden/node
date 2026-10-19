//! Returns a page of latest account commitments, to rebuild the account tree at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::Word;
use miden_protocol::account::AccountId;

use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_FIRST_PAGE: &str = include_str!("select_account_commitments_page.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_account_commitments_page_after.sql");

/// Page of account commitments returned by [`select_account_commitments_paged`].
#[derive(Debug)]
pub struct AccountCommitmentsPage {
    /// The account commitments in this page.
    pub commitments: Vec<(AccountId, Word)>,
    /// If `Some`, there are more results. Use this as the `after_account_id` for the next page.
    pub next_cursor: Option<AccountId>,
}

/// Selects account commitments with pagination.
///
/// Returns up to `page_size` account commitments, starting after `after_account_id` if provided.
/// Results are ordered by `account_id` for stable pagination.
pub(crate) fn select_account_commitments_paged(
    tx: &ReadTx<'_>,
    page_size: NonZeroUsize,
    after_account_id: Option<AccountId>,
) -> Result<AccountCommitmentsPage, DatabaseError> {
    // Fetch one extra to determine if there are more results
    let limit = i64::try_from(page_size.get() + 1).expect("page size fits within i64");

    let mut commitments = match after_account_id {
        Some(cursor) => {
            tx.query(SQL_AFTER_CURSOR, &[&limit, &VALID_FOREVER, &cursor], commitment_from_row)?
        },
        None => tx.query(SQL_FIRST_PAGE, &[&limit, &VALID_FOREVER], commitment_from_row)?,
    };

    // If we got more than page_size, there are more results
    let next_cursor = if commitments.len() > page_size.get() {
        commitments.pop(); // Remove the extra element
        commitments.last().map(|(id, _)| *id)
    } else {
        None
    };

    Ok(AccountCommitmentsPage { commitments, next_cursor })
}

/// Maps a `SELECT account_id, account_commitment` row to its pair.
fn commitment_from_row(row: &Row<'_>) -> Result<(AccountId, Word), miden_node_db::DatabaseError> {
    Ok((row.get::<AccountId>(0)?, row.get::<Word>(1)?))
}
