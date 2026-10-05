//! Returns pages of latest account commitments, to rebuild the account tree at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::Word;
use miden_protocol::account::AccountId;

use crate::db::pagination::{Page, Paginated};
use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_FIRST_PAGE: &str = include_str!("select_account_commitments_page.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_account_commitments_page_after.sql");

/// Paginated query over the latest commitment of every account, ordered by account ID so that the
/// last ID of a page is an unambiguous cursor for the next one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AccountCommitmentsPaged {
    /// Maximum number of account commitments in a page.
    pub page_size: NonZeroUsize,
}

impl Paginated for AccountCommitmentsPaged {
    type Item = (AccountId, Word);
    type Cursor = AccountId;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        after: Option<&AccountId>,
    ) -> Result<Page<(AccountId, Word), AccountId>, DatabaseError> {
        // Fetch one extra to determine if there are more results
        let limit = i64::try_from(self.page_size.get() + 1).expect("page size fits within i64");

        let commitments = match after {
            Some(cursor) => {
                tx.query(SQL_AFTER_CURSOR, &[&limit, &VALID_FOREVER, cursor], commitment_from_row)?
            },
            None => tx.query(SQL_FIRST_PAGE, &[&limit, &VALID_FOREVER], commitment_from_row)?,
        };

        Ok(Page::from_overflow(commitments, self.page_size, |(id, _)| *id))
    }
}

/// Maps a `SELECT account_id, account_commitment` row to its pair.
fn commitment_from_row(row: &Row<'_>) -> Result<(AccountId, Word), miden_node_db::DatabaseError> {
    Ok((row.get::<AccountId>(0)?, row.get::<Word>(1)?))
}
