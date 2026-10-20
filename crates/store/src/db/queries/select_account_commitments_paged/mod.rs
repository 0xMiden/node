//! Returns pages of latest account commitments, to rebuild the account tree at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::Word;
use miden_protocol::account::AccountId;

use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_account_commitments_page.sql");

/// Paginated query over the latest commitment of every account, ordered by account ID.
///
/// The cursor is the account ID where a page starts, or `None` for the first account.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AccountCommitmentsPaged {
    /// Maximum number of account commitments in a page.
    pub page_size: NonZeroUsize,
}

impl Paginated for AccountCommitmentsPaged {
    type Item = (AccountId, Word);
    type Cursor = Option<AccountId>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Option<AccountId>,
    ) -> Result<Page<(AccountId, Word), Option<AccountId>>, DatabaseError> {
        // Fetch one extra to determine if there are more results
        let limit = i64::try_from(self.page_size.get() + 1).expect("page size fits within i64");

        let commitments = tx.query(
            SQL,
            &[&limit, &VALID_FOREVER, &key_cursor(next.as_ref())],
            commitment_from_row,
        )?;

        Ok(Page::from_overflow(commitments, self.page_size, |(id, _)| Some(*id)))
    }
}

/// Maps a `SELECT account_id, account_commitment` row to its pair.
fn commitment_from_row(row: &Row<'_>) -> Result<(AccountId, Word), miden_node_db::DatabaseError> {
    Ok((row.get::<AccountId>(0)?, row.get::<Word>(1)?))
}
