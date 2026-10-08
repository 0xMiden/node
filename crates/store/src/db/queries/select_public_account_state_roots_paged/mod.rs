//! Returns pages of public account state roots, to verify the account state forest at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountStorageHeader};

use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_public_account_state_roots_page.sql");

/// Latest account state forest roots for a public account.
#[derive(Debug)]
pub struct PublicAccountStateRoots {
    pub account_id: AccountId,
    pub vault_root: Word,
    pub storage_header: AccountStorageHeader,
}

/// A stored public account row. The vault root and the storage header columns are nullable.
type StateRootsRow = (AccountId, Option<Word>, Option<AccountStorageHeader>);

/// Paginated query over the latest vault root and storage header of every public account, ordered
/// by account ID. The cursor is the account ID where a page starts, or `None` for the first account.
///
/// Public accounts are recognized by their stored `code_commitment`, because private accounts only
/// store an `account_commitment`. Both columns are nullable in the schema, but a public account
/// always has them, so a page fails with [`DatabaseError::DataCorrupted`] if either is missing.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PublicAccountStateRootsPaged {
    /// Maximum number of public account states in a page.
    pub page_size: NonZeroUsize,
}

impl Paginated for PublicAccountStateRootsPaged {
    type Item = PublicAccountStateRoots;
    type Cursor = Option<AccountId>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Option<AccountId>,
    ) -> Result<Page<PublicAccountStateRoots, Option<AccountId>>, DatabaseError> {
        // Fetch one extra to determine if there are more results
        let limit = i64::try_from(self.page_size.get() + 1).expect("page size fits within i64");

        let rows = tx.query(
            SQL,
            &[&limit, &VALID_FOREVER, &key_cursor(next.as_ref())],
            state_roots_from_row,
        )?;

        // The columns are nullable in the schema, but a public account always has both.
        let accounts = rows
            .into_iter()
            .map(|(account_id, vault_root, storage_header)| {
                Ok(PublicAccountStateRoots {
                    account_id,
                    vault_root: vault_root.ok_or_else(|| {
                        DatabaseError::DataCorrupted(format!(
                            "public account {account_id} is missing a vault root"
                        ))
                    })?,
                    storage_header: storage_header.ok_or_else(|| {
                        DatabaseError::DataCorrupted(format!(
                            "public account {account_id} is missing a storage header"
                        ))
                    })?,
                })
            })
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        Ok(Page::from_overflow(accounts, self.page_size, |account| {
            Some(account.account_id)
        }))
    }
}

/// Maps a `SELECT account_id, vault_root, storage_header` row to its [`StateRootsRow`].
fn state_roots_from_row(row: &Row<'_>) -> Result<StateRootsRow, miden_node_db::DatabaseError> {
    Ok((
        row.get::<AccountId>(0)?,
        row.get::<Option<Word>>(1)?,
        row.get::<Option<AccountStorageHeader>>(2)?,
    ))
}
