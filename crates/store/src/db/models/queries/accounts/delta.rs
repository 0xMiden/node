//! Optimized delta update support for account updates.
//!
//! Provides functions and types for applying partial delta updates to accounts
//! without loading the full account state. Avoids loading:
//! - Full account code bytes
//! - All storage map entries
//! - All vault assets
//!
//! Instead, only the minimal data needed for the update is fetched.

use std::collections::{BTreeMap, HashMap};

use diesel::query_dsl::methods::SelectDsl;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection};
use miden_protocol::account::{
    Account,
    AccountId,
    AccountStorageHeader,
    AccountStoragePatch,
    StorageMap,
    StorageMapKey,
    StorageSlotHeader,
    StorageSlotName,
};
use miden_protocol::asset::Asset;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{EMPTY_WORD, Felt, Word};

use crate::db::models::conv::raw_sql_to_nonce;
use crate::db::schema;
use crate::errors::DatabaseError;

#[cfg(test)]
mod tests;

// TYPES
// ================================================================================================

/// Raw row type for account state delta queries.
///
/// Fields: (`nonce`, `code_commitment`, `storage_header`)
#[derive(diesel::prelude::Queryable)]
struct AccountStateDeltaRow {
    nonce: Option<i64>,
    code_commitment: Option<Vec<u8>>,
    storage_header: Option<Vec<u8>>,
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

/// Represents the account state to be inserted, either from a full account or from a partial delta
/// update.
#[expect(
    clippy::large_enum_variant,
    reason = "built per account update and consumed immediately"
)]
pub(super) enum AccountStateForInsert {
    /// Private account - no public state stored
    Private,
    /// Full account state (from full-state delta, i.e., new account)
    FullAccount(Account),
    /// Partial account state (from partial delta, i.e., existing account update)
    PartialState(PartialAccountState),
}

// QUERIES
// ================================================================================================

/// Selects the minimal account state needed for applying a delta update.
///
/// Optimized query that only fetches:
/// - `nonce` (to add `nonce_delta`)
/// - `code_commitment` (unchanged in partial deltas)
/// - `storage_header` (to apply storage delta)
///
/// # Raw SQL
///
/// ```sql
/// SELECT nonce, code_commitment, storage_header
/// FROM accounts
/// WHERE account_id = ?1 AND is_latest = 1
/// ```
pub(super) fn select_minimal_account_state_headers(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<AccountStateHeadersForDelta, DatabaseError> {
    let row: AccountStateDeltaRow = SelectDsl::select(
        schema::accounts::table,
        (
            schema::accounts::nonce,
            schema::accounts::code_commitment,
            schema::accounts::storage_header,
        ),
    )
    .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
    .filter(schema::accounts::is_latest.eq(true))
    .get_result(conn)
    .optional()?
    .ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;

    let nonce = raw_sql_to_nonce(row.nonce.ok_or_else(|| {
        DatabaseError::DataCorrupted(format!("No nonce found for account {account_id}"))
    })?);

    let code_commitment = row
        .code_commitment
        .map(|bytes| Word::read_from_bytes(&bytes))
        .transpose()?
        .ok_or_else(|| {
            DatabaseError::DataCorrupted(format!(
                "No code_commitment found for account {account_id}"
            ))
        })?;

    let storage_header = match row.storage_header {
        Some(bytes) => AccountStorageHeader::read_from_bytes(&bytes)?,
        None => AccountStorageHeader::new(Vec::new())?,
    };

    Ok(AccountStateHeadersForDelta { nonce, code_commitment, storage_header })
}

/// Selects the latest vault assets for an account.
///
/// # Raw SQL
///
/// ```sql
/// SELECT vault_key, asset
/// FROM account_vault_assets
/// WHERE account_id = ?1 AND is_latest = 1
/// ```
pub(super) fn select_latest_vault_assets(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Vec<Asset>, DatabaseError> {
    use schema::account_vault_assets as vault;

    let entries: Vec<(Vec<u8>, Option<Vec<u8>>)> =
        SelectDsl::select(vault::table, (vault::vault_key, vault::asset))
            .filter(vault::account_id.eq(account_id.to_bytes()))
            .filter(vault::is_latest.eq(true))
            .load(conn)?;

    entries
        .into_iter()
        .filter_map(|(_vault_key_bytes, maybe_asset_bytes)| {
            maybe_asset_bytes.map(|bytes| Asset::read_from_bytes(&bytes))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Applies a storage patch to an existing storage header using precomputed map roots.
///
/// For value slots, updates the slot value directly.
/// For map slots, uses the precomputed roots for updated maps.
pub(super) fn apply_storage_patch(
    header: &AccountStorageHeader,
    patch: &AccountStoragePatch,
    map_entries: &HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>,
) -> Result<AccountStorageHeader, DatabaseError> {
    let mut value_updates: HashMap<&StorageSlotName, Word> = HashMap::new();
    let mut map_updates: HashMap<&StorageSlotName, Word> = HashMap::new();

    for (slot_name, new_value) in patch.values() {
        value_updates.insert(slot_name, *new_value);
    }

    for (slot_name, map_patch) in patch.maps() {
        if map_patch.is_empty() {
            continue;
        }

        let mut entries = map_entries.get(slot_name).cloned().unwrap_or_default();
        for (key, value) in map_patch.entries() {
            if *value == EMPTY_WORD {
                entries.remove(key);
            } else {
                entries.insert(*key, *value);
            }
        }

        let storage_map = StorageMap::with_entries(entries.into_iter())
            .map_err(DatabaseError::StorageMapError)?;
        map_updates.insert(slot_name, storage_map.root());
    }

    let slots = Vec::from_iter(header.slots().map(|slot| {
        let slot_name = slot.name();
        if let Some(&new_value) = value_updates.get(slot_name) {
            StorageSlotHeader::new(slot_name.clone(), slot.slot_type(), new_value)
        } else if let Some(&new_root) = map_updates.get(slot_name) {
            StorageSlotHeader::new(slot_name.clone(), slot.slot_type(), new_root)
        } else {
            slot.clone()
        }
    }));

    AccountStorageHeader::new(slots).map_err(|e| {
        DatabaseError::DataCorrupted(format!("Failed to create storage header: {e:?}"))
    })
}
