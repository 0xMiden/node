//! Returns an account's header as of a block.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader};
use miden_protocol::block::BlockNumber;
use miden_protocol::{Felt, Word};

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_account_header_at_block.sql");

/// The header columns as stored; every one of them is nullable for private accounts.
type AccountHeaderRow = (Option<Word>, Option<Felt>, Option<AccountStorageHeader>, Option<Word>);

/// Queries the account header for a specific account at a specific block number.
///
/// This reconstructs the [`AccountHeader`] by reading from the `accounts` table:
/// `account_id`, `nonce`, `code_commitment`, `storage_header`, `vault_root`.
///
/// # Returns
///
/// * `Ok(Some((AccountHeader, AccountStorageHeader)))` - The headers if found
/// * `Ok(None)` - If account doesn't exist at that block
/// * `Err(DatabaseError)` - If there's a database error
pub(crate) fn select_account_header_with_storage_header_at_block(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<Option<(AccountHeader, AccountStorageHeader)>, DatabaseError> {
    let row = tx
        .query(SQL, &[&account_id, &block_num], |row| -> Result<AccountHeaderRow, _> {
            Ok((
                row.get::<Option<Word>>(0)?,
                row.get::<Option<Felt>>(1)?,
                row.get::<Option<AccountStorageHeader>>(2)?,
                row.get::<Option<Word>>(3)?,
            ))
        })?
        .into_iter()
        .next();

    let Some((code_commitment, nonce, storage_header, vault_root)) = row else {
        return Ok(None);
    };

    // A private account stores none of these, in which case the header reads as empty/default.
    let storage_header = storage_header.unwrap_or(AccountStorageHeader::new(Vec::new())?);
    let storage_commitment = storage_header.to_commitment();

    let account_header = AccountHeader::new(
        account_id,
        nonce.unwrap_or(Felt::ZERO),
        vault_root.unwrap_or_default(),
        storage_commitment,
        code_commitment.unwrap_or_default(),
    );

    Ok(Some((account_header, storage_header)))
}
