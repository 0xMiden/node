//! Returns a page of public account ids, to rebuild the account state forest at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::account::AccountId;

use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_FIRST_PAGE: &str = include_str!("select_public_account_ids_page.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_public_account_ids_page_after.sql");

/// Page of public account IDs returned by [`select_public_account_ids_paged`].
#[derive(Debug)]
pub struct PublicAccountIdsPage {
    /// The public account IDs in this page.
    pub account_ids: Vec<AccountId>,
    /// If `Some`, there are more results. Use this as the `after_account_id` for the next page.
    pub next_cursor: Option<AccountId>,
}

/// Selects public account IDs with pagination.
///
/// Returns up to `page_size` public account IDs, starting after `after_account_id` if provided.
/// Results are ordered by `account_id` for stable pagination.
///
/// Public accounts are those with `AccountType::Public`. We identify them by checking
/// against the store. Public accounts store their `code_commitment`, while private accounts only
/// store the `account_commitment`.
pub(crate) fn select_public_account_ids_paged(
    tx: &ReadTx<'_>,
    page_size: NonZeroUsize,
    after_account_id: Option<AccountId>,
) -> Result<PublicAccountIdsPage, DatabaseError> {
    // Fetch one extra to determine if there are more results
    let limit = i64::try_from(page_size.get() + 1).expect("page size fits within i64");

    let mut account_ids = match after_account_id {
        Some(cursor) => tx.query(SQL_AFTER_CURSOR, &[&limit, &VALID_FOREVER, &cursor], |row| {
            row.get::<AccountId>(0)
        })?,
        None => {
            tx.query(SQL_FIRST_PAGE, &[&limit, &VALID_FOREVER], |row| row.get::<AccountId>(0))?
        },
    };

    // If we got more than page_size, there are more results
    let next_cursor = if account_ids.len() > page_size.get() {
        account_ids.pop(); // Remove the extra element
        account_ids.last().copied()
    } else {
        None
    };

    Ok(PublicAccountIdsPage { account_ids, next_cursor })
}
