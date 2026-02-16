//! Optimized delta update support for account updates.
//!
//! Provides functions and types for applying partial delta updates to accounts
//! without loading the full account state. Avoids loading:
//! - Full account code bytes
//! - All storage map entries
//! - All vault assets
//!
//! Instead, only the minimal data needed for the update is fetched.

use std::collections::BTreeMap;

use diesel::query_dsl::methods::SelectDsl;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection};
use miden_protocol::account::delta::AccountStorageDelta;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountStorageHeader,
    StorageSlotHeader,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::utils::{Deserializable, Serializable};
use miden_protocol::{Felt, Word};

use crate::db::models::conv::raw_sql_to_nonce;
use crate::db::schema;
use crate::errors::DatabaseError;

#[cfg(test)]
mod tests;

// TYPES
// ================================================================================================

/// Raw row type for account state delta queries.
///
/// Fields: (`nonce`, `code_commitment`, `storage_header`, `vault_root`)
#[derive(diesel::prelude::Queryable)]
struct AccountStateDeltaRow {
    nonce: Option<i64>,
    code_commitment: Option<Vec<u8>>,
    storage_header: Option<Vec<u8>>,
    vault_root: Option<Vec<u8>>,
}

/// Data needed for applying a delta update to an existing account.
/// Fetches only the minimal data required, avoiding loading full code and storage.
#[derive(Debug, Clone)]
pub(super) struct AccountStateHeadersForDelta {
    pub nonce: Felt,
    pub code_commitment: Word,
    pub storage_header: AccountStorageHeader,
    pub vault_root: Word,
}

/// Minimal account state computed from a partial delta update.
/// Contains only the fields needed for the accounts table row insert.
#[derive(Debug, Clone)]
pub(super) struct PartialAccountState {
    pub nonce: Felt,
    pub code_commitment: Word,
    pub storage_header: AccountStorageHeader,
    pub vault_root: Word,
}

/// Represents the account state to be inserted, either from a full account
/// or from a partial delta update.
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
/// - `vault_root` (to apply vault delta)
///
/// # Raw SQL
///
/// ```sql
/// SELECT nonce, code_commitment, storage_header, vault_root
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
            schema::accounts::vault_root,
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

    let vault_root = row
        .vault_root
        .map(|bytes| Word::read_from_bytes(&bytes))
        .transpose()?
        .unwrap_or(Word::default());

    Ok(AccountStateHeadersForDelta {
        nonce,
        code_commitment,
        storage_header,
        vault_root,
    })
}

/// Selects vault balances for specific faucet IDs.
///
/// Optimized query that only fetches balances for the faucet IDs
/// that are being updated by a delta, rather than loading all vault assets.
///
/// Returns a map from `faucet_id` to the current balance (0 if not found).
///
/// # Raw SQL
///
/// ```sql
/// SELECT vault_key, asset
/// FROM account_vault_assets
/// WHERE account_id = ?1 AND is_latest = 1 AND vault_key IN (?2, ?3, ...)
/// ```
pub(super) fn select_vault_balances_by_faucet_ids(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    faucet_ids: &[AccountId],
) -> Result<BTreeMap<AccountId, u64>, DatabaseError> {
    use schema::account_vault_assets as vault;

    if faucet_ids.is_empty() {
        return Ok(BTreeMap::new());
    }

    let account_id_bytes = account_id.to_bytes();

    // Compute vault keys for each faucet ID
    let vault_keys: Vec<Vec<u8>> = Result::from_iter(faucet_ids.iter().map(|faucet_id| {
        let asset = FungibleAsset::new(*faucet_id, 0)
            .map_err(|_| DatabaseError::DataCorrupted(format!("Invalid faucet id {faucet_id}")))?;
        let key: Word = asset.vault_key().into();
        Ok::<_, DatabaseError>(key.to_bytes())
    }))?;

    let entries: Vec<(Vec<u8>, Option<Vec<u8>>)> =
        SelectDsl::select(vault::table, (vault::vault_key, vault::asset))
            .filter(vault::account_id.eq(&account_id_bytes))
            .filter(vault::is_latest.eq(true))
            .filter(vault::vault_key.eq_any(&vault_keys))
            .load(conn)?;

    let mut balances = BTreeMap::new();

    for (_vault_key_bytes, maybe_asset_bytes) in entries {
        if let Some(asset_bytes) = maybe_asset_bytes {
            let asset = Asset::read_from_bytes(&asset_bytes)?;
            if let Asset::Fungible(fungible) = asset {
                balances.insert(fungible.faucet_id(), fungible.amount());
            }
        }
    }

    Ok(balances)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Applies storage delta to an existing storage header using precomputed map roots.
///
/// For value slots, updates the slot value directly.
/// For map slots, uses the precomputed roots for updated maps.
pub(super) fn apply_storage_delta_with_precomputed_roots(
    header: &AccountStorageHeader,
    delta: &AccountStorageDelta,
    storage_map_roots: Option<&BTreeMap<StorageSlotName, Word>>,
) -> Result<AccountStorageHeader, DatabaseError> {
    let mut value_updates: BTreeMap<&StorageSlotName, Word> = BTreeMap::new();
    let mut map_updates: BTreeMap<&StorageSlotName, Word> = BTreeMap::new();

    for (slot_name, new_value) in delta.values() {
        value_updates.insert(slot_name, *new_value);
    }

    for (slot_name, map_delta) in delta.maps() {
        if map_delta.is_empty() {
            continue;
        }

        let new_root = storage_map_roots
            .and_then(|roots| roots.get(slot_name).copied())
            .ok_or_else(|| {
                DatabaseError::DataCorrupted(format!(
                    "Missing precomputed storage map root for slot {slot_name}"
                ))
            })?;
        map_updates.insert(slot_name, new_root);
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
