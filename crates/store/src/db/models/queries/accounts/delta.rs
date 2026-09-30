//! Optimized delta update support for account updates.
//!
//! Provides functions and types for applying partial delta updates to accounts
//! without loading the full account state. Avoids loading:
//! - Full account code bytes
//! - All storage map entries
//! - All vault assets
//!
//! Instead, only the minimal data needed for the update is fetched.

use std::collections::{BTreeMap, HashMap, HashSet};

use diesel::query_dsl::methods::SelectDsl;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection};
#[cfg(test)]
use miden_protocol::EMPTY_WORD;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountId,
    AccountStorageHeader,
    AccountStoragePatch,
    StoragePatchOperation,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotType,
};
#[cfg(test)]
use miden_protocol::account::{StorageMap, StorageMapKey};
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Felt, Word};

use super::{NetworkAccountType, VALID_FOREVER};
use crate::db::models::conv::{SqlTypeConvert, raw_sql_to_nonce};
use crate::db::schema;
use crate::errors::DatabaseError;

#[cfg(test)]
mod tests;

// TYPES
// ================================================================================================

/// Latest account row fields needed by account update preparation.
#[derive(diesel::prelude::Queryable)]
pub(super) struct LatestAccountStateRow {
    created_at_block: i64,
    network_account_type: i32,
    nonce: Option<i64>,
    code_commitment: Option<Vec<u8>>,
    storage_header: Option<Vec<u8>>,
}

impl LatestAccountStateRow {
    pub(super) fn created_at_block(&self) -> Result<BlockNumber, DatabaseError> {
        Ok(BlockNumber::from_raw_sql(self.created_at_block)?)
    }

    pub(super) fn network_account_type(&self) -> Result<NetworkAccountType, DatabaseError> {
        Ok(NetworkAccountType::from_raw_sql(self.network_account_type)?)
    }

    pub(super) fn state_headers(
        &self,
        account_id: AccountId,
    ) -> Result<AccountStateHeadersForDelta, DatabaseError> {
        let nonce = raw_sql_to_nonce(self.nonce.ok_or_else(|| {
            DatabaseError::DataCorrupted(format!("No nonce found for account {account_id}"))
        })?);

        let code_commitment = self
            .code_commitment
            .as_deref()
            .map(Word::read_from_bytes)
            .transpose()?
            .ok_or_else(|| {
                DatabaseError::DataCorrupted(format!(
                    "No code_commitment found for account {account_id}"
                ))
            })?;

        let storage_header = match self.storage_header.as_deref() {
            Some(bytes) => miden_node_persistence::decode::<AccountStorageHeader>(bytes)?,
            None => AccountStorageHeader::new(Vec::new())?,
        };

        Ok(AccountStateHeadersForDelta { nonce, code_commitment, storage_header })
    }
}

/// Data needed for applying a delta update to an existing account. Fetches only the minimal data
/// required, avoiding loading full code and storage.
#[derive(Debug, Clone)]
pub(super) struct AccountStateHeadersForDelta {
    pub nonce: Felt,
    pub code_commitment: Word,
    pub storage_header: AccountStorageHeader,
}

/// Minimal account state computed from a partial delta update. Contains only the fields needed for
/// the accounts table row insert.
#[derive(Debug, Clone)]
pub(super) struct PartialAccountState {
    pub nonce: Felt,
    pub code_commitment: Word,
    pub storage_header: AccountStorageHeader,
    pub vault_root: Word,
}

/// Full account state assembled from a full-state patch and precomputed Merkle roots.
#[derive(Debug, Clone)]
pub(super) struct PrecomputedFullAccountState {
    pub nonce: Felt,
    pub code: AccountCode,
    pub storage_header: AccountStorageHeader,
    pub vault_root: Word,
    pub is_network_account: bool,
}

/// Represents the account state to be inserted, either from a full account or from a partial delta
/// update.
pub(super) enum AccountStateForInsert {
    /// Private account - no public state stored
    Private,
    /// Full account state (from full-state delta, i.e., new account)
    FullAccount(Account),
    /// Full account state assembled without reconstructing its vault and storage maps.
    PrecomputedFullState(PrecomputedFullAccountState),
    /// Partial account state (from partial delta, i.e., existing account update)
    PartialState(PartialAccountState),
}

// QUERIES
// ================================================================================================

/// Selects the latest account state needed to prepare any account update.
///
/// The query fetches:
/// - `created_at_block` and `network_account_type` for every update
/// - `nonce` (preserved when a partial patch omits its final nonce)
/// - `code_commitment` (unchanged in partial deltas)
/// - `storage_header` (to apply storage delta)
///
/// # Raw SQL
///
/// ```sql
/// SELECT created_at_block, network_account_type, nonce, code_commitment, storage_header
/// FROM accounts
/// WHERE account_id = ?1 AND valid_until = {VALID_FOREVER}
/// ```
pub(super) fn select_latest_account_state(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Option<LatestAccountStateRow>, DatabaseError> {
    let row = SelectDsl::select(
        schema::accounts::table,
        (
            schema::accounts::created_at_block,
            schema::accounts::network_account_type,
            schema::accounts::nonce,
            schema::accounts::code_commitment,
            schema::accounts::storage_header,
        ),
    )
    .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
    .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
    .get_result(conn)
    .optional()?;

    Ok(row)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Applies a storage patch to an existing storage header using precomputed map roots.
///
/// For value slots, updates the slot value directly.
/// For map slots, uses the precomputed roots for updated maps.
/// Removed slots are dropped from the header and created slots are added to it, mirroring
/// [`miden_protocol::account::AccountStorage`]'s patch application.
#[cfg(test)]
pub(super) fn apply_storage_patch(
    header: &AccountStorageHeader,
    patch: &AccountStoragePatch,
    map_entries: &HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>,
) -> Result<AccountStorageHeader, DatabaseError> {
    let mut value_updates: HashMap<&StorageSlotName, Word> = HashMap::new();
    let mut map_updates: HashMap<&StorageSlotName, Word> = HashMap::new();
    let mut removed: HashSet<&StorageSlotName> = HashSet::new();

    for (slot_name, value_patch) in patch.values() {
        match value_patch.value() {
            Some(value) => {
                value_updates.insert(slot_name, value);
            },
            None => {
                removed.insert(slot_name);
            },
        }
    }

    for (slot_name, map_patch) in patch.maps() {
        let Some(map_patch_entries) = map_patch.entries() else {
            removed.insert(slot_name);
            continue;
        };
        // Empty entries are a no-op for updates, but creating a map slot with no entries is
        // meaningful and must still produce the slot.
        if map_patch_entries.is_empty() && map_patch.patch_op() != StoragePatchOperation::Create {
            continue;
        }

        let mut entries = map_entries.get(slot_name).cloned().unwrap_or_default();
        for (key, value) in map_patch_entries.as_map() {
            if *value == EMPTY_WORD {
                entries.remove(key);
            } else {
                entries.insert(*key, *value);
            }
        }

        let storage_map =
            StorageMap::with_entries(entries).map_err(DatabaseError::StorageMapError)?;
        map_updates.insert(slot_name, storage_map.root());
    }

    let mut slots = header
        .slots()
        .filter(|slot| !removed.contains(slot.name()))
        .map(|slot| {
            let slot_name = slot.name();
            if let Some(new_value) = value_updates.remove(slot_name) {
                StorageSlotHeader::new(slot_name.clone(), slot.slot_type(), new_value)
            } else if let Some(new_root) = map_updates.remove(slot_name) {
                StorageSlotHeader::new(slot_name.clone(), slot.slot_type(), new_root)
            } else {
                slot.clone()
            }
        })
        .collect::<Vec<_>>();

    // Any updates left over belong to slots created by the patch.
    for (slot_name, value) in value_updates {
        slots.push(StorageSlotHeader::new(slot_name.clone(), StorageSlotType::Value, value));
    }
    for (slot_name, root) in map_updates {
        slots.push(StorageSlotHeader::new(slot_name.clone(), StorageSlotType::Map, root));
    }

    slots.sort_by_key(StorageSlotHeader::id);

    AccountStorageHeader::new(slots).map_err(|e| {
        DatabaseError::DataCorrupted(format!("Failed to create storage header: {e:?}"))
    })
}

/// Applies a storage patch to an existing storage header using precomputed map roots.
///
/// Applies value-slot updates, map-slot removal, no-op map updates, and slot creation. Uses the map
/// roots supplied by the caller. It does not load or reconstruct the map entries.
pub(super) fn apply_storage_patch_with_roots(
    header: &AccountStorageHeader,
    patch: &AccountStoragePatch,
    precomputed_map_roots: &BTreeMap<StorageSlotName, Word>,
) -> Result<AccountStorageHeader, DatabaseError> {
    let mut value_updates: HashMap<&StorageSlotName, Word> = HashMap::new();
    let mut map_updates: HashMap<&StorageSlotName, Word> = HashMap::new();
    let mut removed: HashSet<&StorageSlotName> = HashSet::new();

    for (slot_name, value_patch) in patch.values() {
        match value_patch.value() {
            Some(value) => {
                value_updates.insert(slot_name, value);
            },
            None => {
                removed.insert(slot_name);
            },
        }
    }

    for (slot_name, map_patch) in patch.maps() {
        let Some(map_patch_entries) = map_patch.entries() else {
            removed.insert(slot_name);
            continue;
        };
        // Empty entries are a no-op for updates, but creating a map slot with no entries is
        // meaningful and must still produce the slot.
        if map_patch_entries.is_empty() && map_patch.patch_op() != StoragePatchOperation::Create {
            continue;
        }

        let root = precomputed_map_roots.get(slot_name).copied().ok_or_else(|| {
            DatabaseError::DataCorrupted(format!(
                "missing precomputed storage map root for slot {slot_name}"
            ))
        })?;
        map_updates.insert(slot_name, root);
    }

    let mut slots = header
        .slots()
        .filter(|slot| !removed.contains(slot.name()))
        .map(|slot| {
            let slot_name = slot.name();
            if let Some(new_value) = value_updates.remove(slot_name) {
                StorageSlotHeader::new(slot_name.clone(), slot.slot_type(), new_value)
            } else if let Some(new_root) = map_updates.remove(slot_name) {
                StorageSlotHeader::new(slot_name.clone(), slot.slot_type(), new_root)
            } else {
                slot.clone()
            }
        })
        .collect::<Vec<_>>();

    // Any updates left over belong to slots created by the patch.
    for (slot_name, value) in value_updates {
        slots.push(StorageSlotHeader::new(slot_name.clone(), StorageSlotType::Value, value));
    }
    for (slot_name, root) in map_updates {
        slots.push(StorageSlotHeader::new(slot_name.clone(), StorageSlotType::Map, root));
    }

    slots.sort_by_key(StorageSlotHeader::id);

    AccountStorageHeader::new(slots).map_err(|e| {
        DatabaseError::DataCorrupted(format!("Failed to create storage header: {e:?}"))
    })
}
