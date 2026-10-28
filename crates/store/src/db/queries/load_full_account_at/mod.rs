use std::collections::BTreeMap;

use miden_node_db::sqlite::ReadTx;
use miden_node_proto::domain::account::AccountSyncState;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;

use super::{check_account_history_target, select_account_header_with_storage_header_at_block};
use crate::errors::DatabaseError;

/// Loads the public account's headers, storage map entries, and vault assets at the requested
/// block.
pub(crate) fn load_full_account_at(
    tx: &ReadTx<'_>,
    account: AccountId,
    block: BlockNumber,
) -> Result<AccountSyncState, DatabaseError> {
    check_account_history_target(tx, block)?;
    let (header, storage_header) =
        select_account_header_with_storage_header_at_block(tx, account, block)?
            .ok_or(DatabaseError::AccountNotFoundInDb(account))?;
    let mut maps: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
    let entries =
        tx.query(include_str!("select_storage_map_entries.sql"), &[&account, &block], |row| {
            Ok((
                row.get::<StorageSlotName>(0)?,
                row.get::<StorageMapKey>(1)?,
                row.get::<Word>(2)?,
            ))
        })?;
    for (slot, key, value) in entries {
        maps.entry(slot).or_default().insert(key, value);
    }
    let vault = tx
        .query(include_str!("select_vault_assets.sql"), &[&account, &block], |row| {
            row.get::<Asset>(0)
        })?
        .into_iter()
        .map(|asset| (asset.id(), asset.to_value_word()))
        .collect::<BTreeMap<_, _>>();
    Ok(AccountSyncState { header, storage_header, maps, vault })
}
