//! Reconstructs a full account from the tables holding its latest committed state.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountCode, AccountId};
use miden_protocol::asset::{Asset, AssetVault};

use crate::db::queries::{VALID_FOREVER, select_latest_storage};
use crate::errors::DatabaseError;

const SQL_NONCE_AND_CODE: &str = include_str!("select_account_nonce_and_code.sql");
const SQL_VAULT: &str = include_str!("select_account_vault.sql");

/// Reconstruct full Account from database tables for the latest account state
///
/// This function queries the database tables to reconstruct a complete Account object:
/// - Code from `account_codes` table
/// - Nonce and storage header from `accounts` table
/// - Storage map entries from `account_storage_map_values` table
/// - Vault from `account_vault_assets` table
///
/// # Note
///
/// A stop-gap solution to retain store API and construct `AccountInfo` types.
/// The function should ultimately be removed, and any queries be served from the
/// `State` which contains an `SmtForest` to serve the latest and most recent
/// historical data.
// TODO: remove eventually once refactoring is complete
pub(crate) fn select_full_account(
    tx: &ReadTx<'_>,
    account_id: AccountId,
) -> Result<Account, DatabaseError> {
    // Get account metadata (nonce, code_commitment) and code in a single join query
    let (nonce, code) = tx
        .query(SQL_NONCE_AND_CODE, &[&account_id, &VALID_FOREVER], |row| {
            Ok((row.get::<Option<Felt>>(0)?, row.get::<AccountCode>(1)?))
        })?
        .into_iter()
        .next()
        .ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;

    let nonce = nonce.ok_or_else(|| {
        DatabaseError::DataCorrupted(format!("No nonce found for account {account_id}"))
    })?;

    // Reconstruct storage using existing helper function
    let storage = select_latest_storage(tx, account_id)?;

    // Reconstruct vault from account_vault_assets table; a NULL asset marks a removal.
    let assets = tx
        .query(SQL_VAULT, &[&account_id, &VALID_FOREVER], |row| row.get::<Option<Asset>>(0))?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let vault = AssetVault::new(&assets)?;

    Ok(Account::new(account_id, vault, storage, code, nonce, None)?)
}
