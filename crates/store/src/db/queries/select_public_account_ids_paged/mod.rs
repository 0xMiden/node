//! Returns pages of public account ids, to rebuild the account state forest at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::account::AccountId;

use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_public_account_ids_page.sql");

/// Paginated query over the IDs of all public accounts, ordered by account ID.
///
/// Public accounts are recognized by their stored `code_commitment`, because private accounts only
/// store an `account_commitment`. The cursor is the account ID where a page starts, or `None` for
/// the first account.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PublicAccountIdsPaged {
    /// Maximum number of public account IDs in a page.
    pub page_size: NonZeroUsize,
}

impl Paginated for PublicAccountIdsPaged {
    type Item = AccountId;
    type Cursor = Option<AccountId>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Option<AccountId>,
    ) -> Result<Page<AccountId, Option<AccountId>>, DatabaseError> {
        // Fetch one extra to determine if there are more results
        let limit = i64::try_from(self.page_size.get() + 1).expect("page size fits within i64");

        let account_ids =
            tx.query(SQL, &[&limit, &VALID_FOREVER, &key_cursor(next.as_ref())], |row| {
                row.get::<AccountId>(0)
            })?;

        Ok(Page::from_overflow(account_ids, self.page_size, |id| Some(*id)))
    }
}
