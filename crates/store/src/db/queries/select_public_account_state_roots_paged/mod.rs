//! Returns a page of public account state roots, to verify the account state forest at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountStorageHeader};

use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_FIRST_PAGE: &str = include_str!("select_public_account_state_roots_page.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_public_account_state_roots_page_after.sql");

/// Latest account state forest roots for a public account.
#[derive(Debug)]
pub struct PublicAccountStateRoots {
    pub account_id: AccountId,
    pub vault_root: Word,
    pub storage_header: AccountStorageHeader,
}

/// Page of public account state roots returned by [`select_public_account_state_roots_paged`].
#[derive(Debug)]
pub struct PublicAccountStateRootsPage {
    /// The public account state roots in this page.
    pub accounts: Vec<PublicAccountStateRoots>,
    /// If `Some`, there are more results. Use this as the `after_account_id` for the next page.
    pub next_cursor: Option<AccountId>,
}

/// A stored public account row. The vault root and the storage header columns are nullable.
type StateRootsRow = (AccountId, Option<Word>, Option<AccountStorageHeader>);

/// Selects public account vault roots and storage headers with pagination.
///
/// Returns up to `page_size` public account states, starting after `after_account_id` if provided.
/// Results are ordered by `account_id` for stable pagination.
///
/// Public accounts are those with `AccountType::Public`. We identify them by checking
/// against the store. Public accounts store their `code_commitment`, while private accounts only
/// store the `account_commitment`.
///
/// # Errors
///
/// Returns [`DatabaseError::DataCorrupted`] if a public account has no vault root or no storage
/// header.
pub(crate) fn select_public_account_state_roots_paged(
    tx: &ReadTx<'_>,
    page_size: NonZeroUsize,
    after_account_id: Option<AccountId>,
) -> Result<PublicAccountStateRootsPage, DatabaseError> {
    // Fetch one extra to determine if there are more results
    let limit = i64::try_from(page_size.get() + 1).expect("page size fits within i64");

    let rows = match after_account_id {
        Some(cursor) => {
            tx.query(SQL_AFTER_CURSOR, &[&limit, &VALID_FOREVER, &cursor], state_roots_from_row)?
        },
        None => tx.query(SQL_FIRST_PAGE, &[&limit, &VALID_FOREVER], state_roots_from_row)?,
    };

    // The columns are nullable in the schema, but a public account always has both.
    let mut accounts = rows
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

    // If we got more than page_size, there are more results.
    let next_cursor = if accounts.len() > page_size.get() {
        accounts.pop();
        accounts.last().map(|account| account.account_id)
    } else {
        None
    };

    Ok(PublicAccountStateRootsPage { accounts, next_cursor })
}

/// Maps a `SELECT account_id, vault_root, storage_header` row to its [`StateRootsRow`].
fn state_roots_from_row(row: &Row<'_>) -> Result<StateRootsRow, miden_node_db::DatabaseError> {
    Ok((
        row.get::<AccountId>(0)?,
        row.get::<Option<Word>>(1)?,
        row.get::<Option<AccountStorageHeader>>(2)?,
    ))
}
