//! Reconstructs an account's current storage from the header and its map entries.

use std::collections::{BTreeMap, HashMap};

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::{
    AccountId,
    AccountStorage,
    AccountStorageHeader,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
    StorageSlotType,
};

use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_STORAGE_HEADER: &str = include_str!("select_account_storage_header.sql");
const SQL_MAP_ENTRIES: &str = include_str!("select_account_storage_map_entries.sql");

/// An account's storage header together with its map entries, keyed by slot.
pub(crate) type StorageHeaderWithEntries =
    (AccountStorageHeader, HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>);

/// Reconstructs the account's current storage: value slots come from the header, map slots from the
/// stored map entries.
pub(crate) fn select_latest_storage(
    tx: &ReadTx<'_>,
    account_id: AccountId,
) -> Result<AccountStorage, DatabaseError> {
    let (storage_header, map_entries_by_slot) = select_latest_storage_components(tx, account_id)?;

    // Reconstruct StorageSlots from header slots + map entries
    let slots = storage_header
        .slots()
        .map(|slot_header| {
            let slot = match slot_header.slot_type() {
                StorageSlotType::Value => {
                    // For value slots, the header value IS the slot value
                    StorageSlot::with_value(slot_header.name().clone(), slot_header.value())
                },
                StorageSlotType::Map => {
                    // For map slots, reconstruct from map entries
                    let entries =
                        map_entries_by_slot.get(slot_header.name()).cloned().unwrap_or_default();
                    StorageSlot::with_map(
                        slot_header.name().clone(),
                        StorageMap::with_entries(entries)?,
                    )
                },
            };
            Ok(slot)
        })
        .collect::<Result<Vec<_>, DatabaseError>>()?;

    Ok(AccountStorage::new(slots)?)
}

/// Fetch account storage header and all storage maps
pub(crate) fn select_latest_storage_components(
    tx: &ReadTx<'_>,
    account_id: AccountId,
) -> Result<StorageHeaderWithEntries, DatabaseError> {
    // The column is nullable, and the account may have no row at all.
    let storage_blob = tx
        .query(SQL_STORAGE_HEADER, &[&account_id, &VALID_FOREVER], |row| {
            row.get::<Option<AccountStorageHeader>>(0)
        })?
        .into_iter()
        .next()
        .flatten();

    let header = match storage_blob {
        Some(header) => header,
        None => AccountStorageHeader::new(Vec::new())?,
    };

    Ok((header, select_latest_storage_map_entries_all(tx, account_id)?))
}

// TODO this is expensive and should only be called from tests
fn select_latest_storage_map_entries_all(
    tx: &ReadTx<'_>,
    account_id: AccountId,
) -> Result<HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>, DatabaseError> {
    let map_values = tx.query(SQL_MAP_ENTRIES, &[&account_id, &VALID_FOREVER], |row| {
        Ok((
            row.get::<StorageSlotName>(0)?,
            row.get::<StorageMapKey>(1)?,
            row.get::<Word>(2)?,
        ))
    })?;

    let mut map_entries_by_slot: HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>> =
        HashMap::new();
    for (slot_name, key, value) in map_values {
        map_entries_by_slot.entry(slot_name).or_default().insert(key, value);
    }

    Ok(map_entries_by_slot)
}
