//! Returns pages of public account ids, to rebuild the account state forest at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::account::AccountId;

use crate::db::pagination::{Page, Paginated};
use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_FIRST_PAGE: &str = include_str!("select_public_account_ids_page.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_public_account_ids_page_after.sql");

/// Paginated query over the IDs of all public accounts, ordered by account ID.
///
/// Public accounts are recognized by their stored `code_commitment`, because private accounts only
/// store an `account_commitment`. The cursor is the last account ID of a page.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PublicAccountIdsPaged {
    /// Maximum number of public account IDs in a page.
    pub page_size: NonZeroUsize,
}

impl Paginated for PublicAccountIdsPaged {
    type Item = AccountId;
    type Cursor = AccountId;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        after: Option<&AccountId>,
    ) -> Result<Page<AccountId, AccountId>, DatabaseError> {
        // Fetch one extra to determine if there are more results
        let limit = i64::try_from(self.page_size.get() + 1).expect("page size fits within i64");

        let account_ids = match after {
            Some(cursor) => {
                tx.query(SQL_AFTER_CURSOR, &[&limit, &VALID_FOREVER, cursor], |row| {
                    row.get::<AccountId>(0)
                })?
            },
            None => {
                tx.query(SQL_FIRST_PAGE, &[&limit, &VALID_FOREVER], |row| row.get::<AccountId>(0))?
            },
        };

        Ok(Page::from_overflow(account_ids, self.page_size, |id| *id))
    }
}
