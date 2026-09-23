//! Writes the account state produced by a block.
//!
//! Every account table is versioned: a row is applicable for blocks in `[block_num, valid_until)`,
//! and writing a new version closes the previous one. This module owns that bookkeeping for the
//! `accounts` row itself and drives the per-key writes in
//! [`insert_vault_asset`](super::insert_vault_asset) and
//! [`insert_storage_map_value`](super::insert_storage_map_value).

use std::collections::BTreeMap;

use miden_node_db::sqlite::WriteTx;
use miden_node_tracing::miden_instrument;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountHeader,
    AccountId,
    AccountPatch,
    AccountStorageHeader,
    AccountUpdateDetails,
    StorageMapKey,
    StorageMapPatchEntries,
    StorageSlotContent,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::{BlockAccountUpdate, BlockNumber};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::NetworkAccount;

use crate::COMPONENT;
use crate::db::queries::insert_storage_map_value::insert_storage_map_value_inner;
use crate::db::queries::{
    NetworkAccountType,
    VALID_FOREVER,
    insert_storage_map_value,
    insert_vault_asset,
};
use crate::errors::DatabaseError;

mod delta;
use delta::{
    AccountStateForInsert,
    LatestAccountStateRow,
    PartialAccountState,
    PrecomputedFullAccountState,
    apply_storage_patch_with_roots,
    select_latest_account_state,
};

#[cfg(test)]
mod tests;

const SQL_INSERT_ACCOUNT_CODE: &str = include_str!("insert_account_code.sql");
const SQL_CLOSE_ACCOUNT_VALIDITY: &str = include_str!("close_account_validity.sql");
const SQL_UPSERT_ACCOUNT: &str = include_str!("upsert_account.sql");

// PRECOMPUTED PUBLIC ACCOUNT STATE
// ================================================================================================

/// Public account state commitments computed by the account state forest before SQLite writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecomputedPublicAccountState {
    pub vault_root: Word,
    pub storage_map_roots: BTreeMap<StorageSlotName, Word>,
}

pub type PrecomputedPublicAccountStates = BTreeMap<AccountId, PrecomputedPublicAccountState>;

// QUERY
// ================================================================================================

type PendingStorageInserts = Vec<(AccountId, StorageSlotName, StorageMapKey, Word)>;
type PendingAssetInserts = Vec<(AccountId, AssetId, Option<Asset>)>;

/// Writes the state of every account a block updated.
///
/// Attention: Assumes the account details are NOT null! The schema explicitly allows this though!
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub(crate) fn upsert_accounts(
    tx: &WriteTx<'_>,
    accounts: &[BlockAccountUpdate],
    block_num: BlockNumber,
    precomputed_public_states: &PrecomputedPublicAccountStates,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    for update in accounts {
        upsert_account(tx, update, block_num, precomputed_public_states)?;
        count += 1;
    }

    Ok(count)
}

/// Writes a single account's new state, closing its previous version's validity interval.
fn upsert_account(
    tx: &WriteTx<'_>,
    update: &BlockAccountUpdate,
    block_num: BlockNumber,
    precomputed_public_states: &PrecomputedPublicAccountStates,
) -> Result<(), DatabaseError> {
    let account_id = update.account_id();

    // Pull the latest row once. Partial updates consume the state headers below, while every update
    // carries forward creation metadata.
    let existing = select_latest_account_state(tx, account_id)?;
    let account_is_new = existing.is_none();

    let created_at_block =
        existing.as_ref().map_or(block_num, LatestAccountStateRow::created_at_block);

    // NOTE: we collect storage / asset inserts to apply them only after the account row is written.
    // The storage and vault tables have FKs pointing to accounts `(account_id, block_num)`, so
    // inserting them earlier would violate those constraints when inserting a brand-new account.
    let (account_state, pending_storage_inserts, pending_asset_inserts) =
        prepare_account_update(update, block_num, precomputed_public_states, existing.as_ref())?;

    // Inherit the classification when the account already exists; otherwise classify it once at
    // creation based on the new state.
    let network_account_type = match &existing {
        Some(row) => row.network_account_type(),
        None => match &account_state {
            AccountStateForInsert::FullAccount(account)
                if NetworkAccount::new(account.clone()).is_ok() =>
            {
                NetworkAccountType::Network
            },
            AccountStateForInsert::PrecomputedFullState(state) if state.is_network_account => {
                NetworkAccountType::Network
            },
            _ => NetworkAccountType::None,
        },
    };

    // Insert account _code_ for full accounts (new account creation).
    match &account_state {
        AccountStateForInsert::FullAccount(account) => insert_account_code(tx, account.code())?,
        AccountStateForInsert::PrecomputedFullState(state) => insert_account_code(tx, &state.code)?,
        AccountStateForInsert::Private | AccountStateForInsert::PartialState(_) => {},
    }

    // Close the previous row's validity interval and insert the NEW account row.
    tx.execute(SQL_CLOSE_ACCOUNT_VALIDITY, &[&block_num, &account_id, &VALID_FOREVER])?;

    let row = AccountRow::new(
        account_id,
        network_account_type,
        update.final_state_commitment(),
        block_num,
        created_at_block,
        &account_state,
    );
    row.upsert(tx)?;

    // Insert pending storage map entries. TODO consider batching
    for (acc_id, slot_name, key, value) in pending_storage_inserts {
        if account_is_new {
            // A brand-new account cannot have a previous open row to invalidate.
            insert_storage_map_value_inner(tx, acc_id, block_num, &slot_name, key, value, false)?;
        } else {
            insert_storage_map_value(tx, acc_id, block_num, &slot_name, key, value)?;
        }
    }

    for (acc_id, vault_key, asset) in pending_asset_inserts {
        insert_vault_asset(tx, acc_id, block_num, vault_key, asset)?;
    }

    Ok(())
}

/// Stores an account's code, keyed by its commitment; a commitment already present is left as is.
fn insert_account_code(tx: &WriteTx<'_>, code: &AccountCode) -> Result<(), DatabaseError> {
    tx.execute(SQL_INSERT_ACCOUNT_CODE, &[&code.commitment(), code])?;
    Ok(())
}

// UPDATE PREPARATION
// ================================================================================================

/// Turns a block's account update into the row state to write, plus the storage-map and vault
/// writes that follow it.
fn prepare_account_update(
    update: &BlockAccountUpdate,
    block_num: BlockNumber,
    precomputed_public_states: &PrecomputedPublicAccountStates,
    existing: Option<&LatestAccountStateRow>,
) -> Result<(AccountStateForInsert, PendingStorageInserts, PendingAssetInserts), DatabaseError> {
    let account_id = update.account_id();

    match update.details() {
        AccountUpdateDetails::Private => Ok((AccountStateForInsert::Private, vec![], vec![])),

        // New account is always a full account, but also comes as an update
        AccountUpdateDetails::Public(patch) if patch.is_full_state() => {
            if block_num == BlockNumber::GENESIS {
                let account = Account::try_from(patch)
                    .expect("Patch to full account always works for full state patches");
                debug_assert_eq!(account_id, account.id());
                prepare_full_account_update(update, account)
            } else {
                let precomputed = precomputed_state(precomputed_public_states, account_id)?;
                prepare_precomputed_full_account_update(update, patch, precomputed)
            }
        },

        // Update of an existing account
        AccountUpdateDetails::Public(patch) => {
            let precomputed = precomputed_state(precomputed_public_states, account_id)?;
            let existing = existing.ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;
            prepare_partial_account_update(update, account_id, patch, precomputed, existing)
        },
    }
}

/// Looks up the forest-computed state for a public account, which every non-genesis public update
/// requires.
fn precomputed_state(
    precomputed_public_states: &PrecomputedPublicAccountStates,
    account_id: AccountId,
) -> Result<&PrecomputedPublicAccountState, DatabaseError> {
    precomputed_public_states.get(&account_id).ok_or_else(|| {
        DatabaseError::DataCorrupted(format!(
            "missing precomputed public account state for account {account_id}"
        ))
    })
}

fn prepare_full_account_update(
    update: &BlockAccountUpdate,
    account: Account,
) -> Result<(AccountStateForInsert, PendingStorageInserts, PendingAssetInserts), DatabaseError> {
    let account_id = account.id();

    // sanity check the commitment of account matches the final state commitment
    if account.to_commitment() != update.final_state_commitment() {
        return Err(DatabaseError::AccountCommitmentsMismatch {
            calculated: account.to_commitment(),
            expected: update.final_state_commitment(),
        });
    }

    // collect storage-map inserts to apply after account upsert
    let mut storage = Vec::new();
    for slot in account.storage().slots() {
        if let StorageSlotContent::Map(storage_map) = slot.content() {
            for (key, value) in storage_map.entries() {
                storage.push((account_id, slot.name().clone(), *key, *value));
            }
        }
    }

    // collect vault-asset inserts to apply after account upsert
    let mut assets = Vec::new();
    for asset in account.vault().assets() {
        // Only insert assets with non-zero values for fungible assets
        let should_insert =
            asset.as_fungible().is_none_or(|fungible| fungible.amount().as_u64() > 0);
        if should_insert {
            assets.push((account_id, asset.id(), Some(asset)));
        }
    }

    Ok((AccountStateForInsert::FullAccount(account), storage, assets))
}

/// Prepares a full public-account insertion using roots computed by the account-state forest.
///
/// This avoids reconstructing the account's vault and storage maps in SQLite. The returned state
/// contains the account-row fields, while storage-map entries and vault assets are returned
/// separately for insertion after the account row has satisfied their foreign-key dependency.
/// Empty-word map entries and assets are omitted from the pending inserts.
///
/// # Errors
///
/// Returns an error if the full-state patch is missing its code or nonce, a required precomputed
/// storage root is absent, an asset is invalid, or the reconstructed account header does not match
/// the update's final state commitment.
fn prepare_precomputed_full_account_update(
    update: &BlockAccountUpdate,
    patch: &AccountPatch,
    precomputed: &PrecomputedPublicAccountState,
) -> Result<(AccountStateForInsert, PendingStorageInserts, PendingAssetInserts), DatabaseError> {
    let account_id = patch.id();
    let code = patch.code().cloned().ok_or_else(|| {
        DatabaseError::DataCorrupted(format!(
            "full-state patch for account {account_id} is missing account code"
        ))
    })?;
    let nonce = patch.final_nonce().ok_or_else(|| {
        DatabaseError::DataCorrupted(format!(
            "full-state patch for account {account_id} is missing final nonce"
        ))
    })?;

    let storage_header = apply_storage_patch_with_roots(
        &AccountStorageHeader::new(Vec::new())?,
        patch.storage(),
        &precomputed.storage_map_roots,
    )?;
    let account_header = AccountHeader::new(
        account_id,
        nonce,
        precomputed.vault_root,
        storage_header.to_commitment(),
        code.commitment(),
    );
    if account_header.to_commitment() != update.final_state_commitment() {
        return Err(DatabaseError::AccountCommitmentsMismatch {
            calculated: account_header.to_commitment(),
            expected: update.final_state_commitment(),
        });
    }

    let storage = patch
        .storage()
        .maps()
        .flat_map(|(slot_name, map_patch)| {
            map_patch.entries().into_iter().flat_map(move |entries| {
                entries
                    .as_map()
                    .iter()
                    .filter(|(_key, value)| **value != Word::empty())
                    .map(move |(key, value)| (account_id, slot_name.clone(), *key, *value))
            })
        })
        .collect();
    let assets = patch
        .vault()
        .iter()
        .filter(|(_asset_id, value)| **value != Word::empty())
        .map(|(asset_id, value)| {
            Asset::new(*asset_id, *value).map(|asset| (account_id, *asset_id, Some(asset)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // The patch carries full state, so it can be turned back into an account and classified with
    // the canonical check.
    let is_network_account = NetworkAccount::new(Account::try_from(patch)?).is_ok();
    let state = PrecomputedFullAccountState {
        nonce,
        code,
        storage_header,
        vault_root: precomputed.vault_root,
        is_network_account,
    };

    Ok((AccountStateForInsert::PrecomputedFullState(state), storage, assets))
}

/// Prepares a partial public-account update using the latest row and precomputed forest roots.
///
/// Unchanged header fields are carried forward from `existing`. The returned partial state is used
/// for the next account row, while storage-map values and vault asset updates are returned
/// separately for insertion after that row. Empty vault values are represented as removals.
///
/// # Errors
///
/// Returns an error if the existing row is invalid, a required precomputed storage root is absent,
/// a patched asset is invalid, or the reconstructed account header does not match the update's
/// final state commitment.
fn prepare_partial_account_update(
    update: &BlockAccountUpdate,
    account_id: AccountId,
    patch: &AccountPatch,
    precomputed: &PrecomputedPublicAccountState,
    existing: &LatestAccountStateRow,
) -> Result<(AccountStateForInsert, PendingStorageInserts, PendingAssetInserts), DatabaseError> {
    // Build the minimal account state needed for partial patch application from the latest row that
    // was loaded with the account's creation metadata.
    let state_headers = existing.state_headers(account_id)?;

    // --- Process asset updates. --------------------------------- The patch carries absolute final
    // values, so encode `Some` as update and `None` (an empty value word) as removal.
    let mut assets = Vec::new();
    for (vault_key, value) in patch.vault().iter() {
        let update_or_remove = if *value == Word::empty() {
            None
        } else {
            Some(Asset::new(*vault_key, *value)?)
        };
        assets.push((account_id, *vault_key, update_or_remove));
    }

    // --- Collect storage map updates. ---------------------------

    let mut storage = Vec::new();
    for (slot_name, map_patch) in patch.storage().maps() {
        for (key, value) in map_patch.entries().into_iter().flat_map(StorageMapPatchEntries::as_map)
        {
            storage.push((account_id, slot_name.clone(), *key, *value));
        }
    }

    // Apply the patch storage to the given storage header.
    let new_storage_header = apply_storage_patch_with_roots(
        &state_headers.storage_header,
        patch.storage(),
        &precomputed.storage_map_roots,
    )?;

    let new_vault_root = precomputed.vault_root;

    // --- Compute updated account state for the accounts row. --- Use the absolute final nonce.
    let new_nonce = patch.final_nonce().unwrap_or(state_headers.nonce);

    // Create minimal account state data for the row insert.
    let account_state = PartialAccountState {
        nonce: new_nonce,
        code_commitment: state_headers.code_commitment,
        storage_header: new_storage_header,
        vault_root: new_vault_root,
    };

    let account_header = AccountHeader::new(
        account_id,
        account_state.nonce,
        account_state.vault_root,
        account_state.storage_header.to_commitment(),
        account_state.code_commitment,
    );

    if account_header.to_commitment() != update.final_state_commitment() {
        return Err(DatabaseError::AccountCommitmentsMismatch {
            calculated: account_header.to_commitment(),
            expected: update.final_state_commitment(),
        });
    }

    Ok((AccountStateForInsert::PartialState(account_state), storage, assets))
}

// ACCOUNT ROW
// ================================================================================================

/// The `accounts` row written for an account's new state.
///
/// Private accounts carry no public state, so every optional column is `None` for them.
pub(crate) struct AccountRow {
    account_id: AccountId,
    network_account_type: NetworkAccountType,
    block_num: BlockNumber,
    account_commitment: Word,
    code_commitment: Option<Word>,
    nonce: Option<Felt>,
    storage_header: Option<AccountStorageHeader>,
    vault_root: Option<Word>,
    created_at_block: BlockNumber,
}

impl AccountRow {
    /// Builds the row for the given prepared account state.
    fn new(
        account_id: AccountId,
        network_account_type: NetworkAccountType,
        account_commitment: Word,
        block_num: BlockNumber,
        created_at_block: BlockNumber,
        state: &AccountStateForInsert,
    ) -> Self {
        let mut row = Self::new_private(
            account_id,
            network_account_type,
            account_commitment,
            block_num,
            created_at_block,
        );

        match state {
            AccountStateForInsert::Private => {},
            AccountStateForInsert::FullAccount(account) => {
                row.code_commitment = Some(account.code().commitment());
                row.nonce = Some(account.nonce());
                row.storage_header = Some(account.storage().to_header());
                row.vault_root = Some(account.vault().root());
            },
            AccountStateForInsert::PrecomputedFullState(state) => {
                row.code_commitment = Some(state.code.commitment());
                row.nonce = Some(state.nonce);
                row.storage_header = Some(state.storage_header.clone());
                row.vault_root = Some(state.vault_root);
            },
            AccountStateForInsert::PartialState(state) => {
                row.code_commitment = Some(state.code_commitment);
                row.nonce = Some(state.nonce);
                row.storage_header = Some(state.storage_header.clone());
                row.vault_root = Some(state.vault_root);
            },
        }

        row
    }

    /// Builds the row for a private account, which has no public state.
    pub(crate) fn new_private(
        account_id: AccountId,
        network_account_type: NetworkAccountType,
        account_commitment: Word,
        block_num: BlockNumber,
        created_at_block: BlockNumber,
    ) -> Self {
        Self {
            account_id,
            network_account_type,
            block_num,
            account_commitment,
            code_commitment: None,
            nonce: None,
            storage_header: None,
            vault_root: None,
            created_at_block,
        }
    }

    /// Writes the row as the account's current, open-ended version.
    pub(crate) fn upsert(&self, tx: &WriteTx<'_>) -> Result<usize, DatabaseError> {
        Ok(tx.execute(
            SQL_UPSERT_ACCOUNT,
            &[
                &self.account_id,
                &self.network_account_type,
                &self.block_num,
                &self.account_commitment,
                &self.code_commitment,
                &self.nonce,
                &self.storage_header,
                &self.vault_root,
                &self.created_at_block,
                &VALID_FOREVER,
            ],
        )?)
    }
}
