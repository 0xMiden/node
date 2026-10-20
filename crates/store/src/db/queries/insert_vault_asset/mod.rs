//! Writes a versioned account vault asset.

use miden_node_db::sqlite::WriteTx;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::BlockNumber;

use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_CLOSE: &str = include_str!("close_vault_asset_validity.sql");
const SQL_INSERT: &str = include_str!("insert_vault_asset.sql");

/// Inserts an account vault asset row.
///
/// The new row is inserted open-ended (`valid_until = VALID_FOREVER`); any existing open row with
/// the same `(account_id, vault_key)` tuple has its validity interval closed at `block_num`. A
/// `None` asset records the removal of that vault key.
///
/// # Returns
///
/// The number of affected rows.
pub(crate) fn insert_vault_asset(
    tx: &WriteTx<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
    vault_key: AssetId,
    asset: Option<Asset>,
) -> Result<usize, DatabaseError> {
    // The column stores the asset id as its word representation.
    let vault_key = Word::from(vault_key);

    // Close the previous version's validity interval at the new row's block.
    let mut count =
        tx.execute(SQL_CLOSE, &[&block_num, &account_id, &vault_key, &VALID_FOREVER])?;

    count +=
        tx.execute(SQL_INSERT, &[&account_id, &block_num, &vault_key, &asset, &VALID_FOREVER])?;

    Ok(count)
}
