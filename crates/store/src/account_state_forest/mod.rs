use std::collections::{BTreeMap, BTreeSet};

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::merkle::smt::{SMT_DEPTH, SmtForest};
use miden_node_proto::domain::account::AccountStorageMapDetails;
use miden_protocol::account::delta::{AccountDelta, AccountStorageDelta, AccountVaultDelta};
use miden_protocol::account::{
    AccountId,
    NonFungibleDeltaAction,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotName,
};
use miden_protocol::asset::{AssetVaultKey, AssetWitness, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::{EmptySubtreeRoots, MerkleError};
use miden_protocol::errors::{AssetError, StorageMapError};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{EMPTY_WORD, Word};
use thiserror::Error;
use tracing::instrument;

use crate::COMPONENT;
pub use crate::db::models::queries::HISTORICAL_BLOCK_RETENTION;

#[cfg(test)]
mod tests;

// ERRORS
// ================================================================================================

#[derive(Debug, Error)]
pub enum AccountStateForestError {
    #[error(transparent)]
    Asset(#[from] AssetError),
    #[error(transparent)]
    Merkle(#[from] MerkleError),
}

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("root not found")]
    RootNotFound,
    #[error("merkle error")]
    MerkleError(#[from] MerkleError),
    #[error("storage map error")]
    StorageMapError(#[from] StorageMapError),
    #[error("failed to construct asset")]
    AssetError(#[from] AssetError),
}

// ACCOUNT STATE FOREST
// ================================================================================================

/// A lineage identifier for trees in the forest.
///
/// This is a local replacement for the removed `LineageId` type. It uniquely identifies
/// a lineage of SMT trees (e.g., per-account vault or per-account-slot storage map).
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct LineageId([u8; 32]);

impl LineageId {
    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Container for forest-related state that needs to be updated atomically.
pub(crate) struct AccountStateForest {
    /// `SmtForest` for efficient account storage reconstruction.
    /// Populated during block import with storage and vault SMTs.
    forest: SmtForest,

    /// Maps lineage IDs to a version-ordered list of (version, root) pairs.
    /// This replaces the lineage/version tracking that was previously internal to
    /// `LargeSmtForest`.
    lineage_versions: BTreeMap<LineageId, Vec<(u64, Word)>>,
}

impl AccountStateForest {
    pub(crate) fn new() -> Self {
        Self {
            forest: SmtForest::new(),
            lineage_versions: BTreeMap::new(),
        }
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of an empty SMT.
    const fn empty_smt_root() -> Word {
        *EmptySubtreeRoots::entry(SMT_DEPTH, 0)
    }

    #[cfg(test)]
    fn tree_id_for_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<Word> {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        self.get_root_at_block(lineage, block_num)
    }

    #[cfg(test)]
    fn tree_id_for_vault_root(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Option<Word> {
        let lineage = Self::vault_lineage_id(account_id);
        self.get_root_at_block(lineage, block_num)
    }

    fn storage_lineage_id(account_id: AccountId, slot_name: &StorageSlotName) -> LineageId {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&account_id.to_bytes());
        bytes.extend_from_slice(slot_name.as_str().as_bytes());
        LineageId::new(Rpo256::hash(&bytes).as_bytes())
    }

    fn vault_lineage_id(account_id: AccountId) -> LineageId {
        LineageId::new(Rpo256::hash(&account_id.to_bytes()).as_bytes())
    }

    /// Returns the latest root for a lineage, or `None` if the lineage is not tracked.
    fn latest_root(&self, lineage: LineageId) -> Option<Word> {
        self.lineage_versions
            .get(&lineage)
            .and_then(|versions| versions.last().map(|(_, root)| *root))
    }

    /// Returns the latest version number for a lineage, or `None` if not tracked.
    fn latest_version(&self, lineage: LineageId) -> Option<u64> {
        self.lineage_versions
            .get(&lineage)
            .and_then(|versions| versions.last().map(|(v, _)| *v))
    }

    /// Applies forest updates for a lineage at a given block number.
    ///
    /// Returns the new root.
    fn apply_forest_updates(
        &mut self,
        lineage: LineageId,
        block_num: BlockNumber,
        entries: Vec<(Word, Word)>,
    ) -> Word {
        let version = block_num.as_u64();

        // Get the current root for this lineage (or empty root).
        let current_root = self.latest_root(lineage).unwrap_or_else(Self::empty_smt_root);

        // Apply all entries via batch_insert on the SmtForest.
        let new_root = if entries.is_empty() {
            current_root
        } else {
            self.forest
                .batch_insert(current_root, entries)
                .expect("forest update should succeed")
        };

        // Record the new version.
        self.lineage_versions.entry(lineage).or_default().push((version, new_root));

        new_root
    }

    /// Finds the root for a lineage at or before the given block number.
    fn get_root_at_block(&self, lineage: LineageId, block_num: BlockNumber) -> Option<Word> {
        let versions = self.lineage_versions.get(&lineage)?;
        let target = block_num.as_u64();
        // Find the latest version <= target.
        let mut result = None;
        for &(v, root) in versions {
            if v <= target {
                result = Some(root);
            } else {
                break;
            }
        }
        result
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Retrieves a vault root for the specified account and block.
    #[cfg(test)]
    pub(crate) fn get_vault_root(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Option<Word> {
        let lineage = Self::vault_lineage_id(account_id);
        self.get_root_at_block(lineage, block_num)
    }

    /// Retrieves the storage map root for an account slot at the specified block.
    #[cfg(test)]
    pub(crate) fn get_storage_map_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<Word> {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        self.get_root_at_block(lineage, block_num)
    }

    // WITNESSES and PROOFS
    // --------------------------------------------------------------------------------------------

    /// Retrieves a storage map witness for the specified account and storage slot.
    ///
    /// Note that the `raw_key` is the raw, user-provided key that needs to be hashed in order to
    /// get the actual key into the storage map.
    pub(crate) fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
        raw_key: StorageMapKey,
    ) -> Result<StorageMapWitness, WitnessError> {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        let root = self.get_root_at_block(lineage, block_num).ok_or(WitnessError::RootNotFound)?;
        let key = raw_key.hash().into();
        let proof = self.forest.open(root, key)?;

        Ok(StorageMapWitness::new(proof, vec![raw_key])?)
    }

    /// Retrieves a vault asset witnesses for the specified account and asset keys at the specified
    /// block number.
    pub fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        asset_keys: BTreeSet<AssetVaultKey>,
    ) -> Result<Vec<AssetWitness>, WitnessError> {
        let lineage = Self::vault_lineage_id(account_id);
        let root = self.get_root_at_block(lineage, block_num).ok_or(WitnessError::RootNotFound)?;
        let witnessees: Result<Vec<_>, WitnessError> =
            Result::from_iter(asset_keys.into_iter().map(|key| {
                let proof = self.forest.open(root, key.into())?;
                let asset = AssetWitness::new(proof)?;
                Ok(asset)
            }));
        witnessees
    }

    /// Opens a storage map and returns storage map details with SMT proofs for the given keys.
    ///
    /// Returns `None` if no storage root is tracked for this account/slot/block combination.
    /// Returns a `MerkleError` if the forest doesn't contain sufficient data for the proofs.
    pub(crate) fn get_storage_map_details_for_keys(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
        raw_keys: &[StorageMapKey],
    ) -> Option<Result<AccountStorageMapDetails, MerkleError>> {
        let lineage = Self::storage_lineage_id(account_id, &slot_name);
        let root = self.get_root_at_block(lineage, block_num)?;

        let proofs = Result::from_iter(raw_keys.iter().map(|raw_key| {
            let key_hashed = raw_key.hash().into();
            self.forest.open(root, key_hashed)
        }));

        Some(proofs.map(|proofs| AccountStorageMapDetails::from_proofs(slot_name, proofs)))
    }

    // PUBLIC INTERFACE
    // --------------------------------------------------------------------------------------------

    /// Updates the forest with account vault and storage changes from a delta.
    ///
    /// Iterates through account updates and applies each delta to the forest.
    /// Private accounts should be filtered out before calling this method.
    ///
    /// # Arguments
    ///
    /// * `block_num` - Block number for which these updates apply
    /// * `account_updates` - Iterator of `AccountDelta` for public accounts
    ///
    /// # Errors
    ///
    /// Returns an error if applying a vault delta results in a negative balance.
    #[instrument(target = COMPONENT, skip_all, fields(block.number = %block_num))]
    pub(crate) fn apply_block_updates(
        &mut self,
        block_num: BlockNumber,
        account_updates: impl IntoIterator<Item = AccountDelta>,
    ) -> Result<(), AccountStateForestError> {
        for delta in account_updates {
            self.update_account(block_num, &delta)?;

            tracing::debug!(
                target: crate::COMPONENT,
                account_id = %delta.id(),
                %block_num,
                is_full_state = delta.is_full_state(),
                "Updated forest with account delta"
            );
        }

        self.prune(block_num);

        Ok(())
    }

    /// Updates the forest with account vault and storage changes from a delta.
    ///
    /// Unified interface for updating all account state in the forest, handling both full-state
    /// deltas (new accounts or reconstruction from DB) and partial deltas (incremental updates
    /// during block application).
    ///
    /// Full-state deltas (`delta.is_full_state() == true`) populate the forest from scratch using
    /// an empty SMT root. Partial deltas apply changes on top of the previous block's state.
    ///
    /// # Errors
    ///
    /// Returns an error if applying a vault delta results in a negative balance.
    pub(crate) fn update_account(
        &mut self,
        block_num: BlockNumber,
        delta: &AccountDelta,
    ) -> Result<(), AccountStateForestError> {
        let account_id = delta.id();
        let is_full_state = delta.is_full_state();

        // Apply vault changes.
        if is_full_state {
            self.insert_account_vault(block_num, account_id, delta.vault())?;
        } else if !delta.vault().is_empty() {
            self.update_account_vault(block_num, account_id, delta.vault())?;
        }

        // Apply storage map changes.
        if is_full_state {
            self.insert_account_storage(block_num, account_id, delta.storage());
        } else if !delta.storage().is_empty() {
            self.update_account_storage(block_num, account_id, delta.storage());
        }

        Ok(())
    }

    // ASSET VAULT DELTA PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Retrieves the most recent vault SMT root for an account. If no vault root is found for the
    /// account, returns an empty SMT root.
    fn get_latest_vault_root(&self, account_id: AccountId) -> Word {
        let lineage = Self::vault_lineage_id(account_id);
        self.latest_root(lineage).unwrap_or_else(Self::empty_smt_root)
    }

    /// Inserts asset vault data into the forest for the specified account. Assumes that asset
    /// vault for this account does not yet exist in the forest.
    fn insert_account_vault(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        vault_delta: &AccountVaultDelta,
    ) -> Result<(), AccountStateForestError> {
        let prev_root = self.get_latest_vault_root(account_id);
        let lineage = Self::vault_lineage_id(account_id);
        assert_eq!(prev_root, Self::empty_smt_root(), "account should not be in the forest");
        assert!(self.latest_version(lineage).is_none(), "account should not be in the forest");

        if vault_delta.is_empty() {
            let lineage = Self::vault_lineage_id(account_id);
            let new_root = self.apply_forest_updates(lineage, block_num, Vec::new());

            tracing::debug!(
                target: crate::COMPONENT,
                %account_id,
                %block_num,
                %new_root,
                vault_entries = 0,
                "Inserted vault into forest"
            );
            return Ok(());
        }

        let mut entries: Vec<(Word, Word)> = Vec::new();

        for (faucet_id, amount_delta) in vault_delta.fungible().iter() {
            let amount =
                (*amount_delta).try_into().expect("full-state amount should be non-negative");
            let asset = FungibleAsset::new(*faucet_id, amount)?;
            entries.push((asset.to_key_word(), asset.to_value_word()));
        }

        // process non-fungible assets
        for (&asset, action) in vault_delta.non_fungible().iter() {
            let asset_vault_key: Word = asset.vault_key().into();
            match action {
                NonFungibleDeltaAction::Add => {
                    entries.push((asset_vault_key, asset.to_value_word()));
                },
                NonFungibleDeltaAction::Remove => entries.push((asset_vault_key, EMPTY_WORD)),
            }
        }

        let num_entries = entries.len();

        let lineage = Self::vault_lineage_id(account_id);
        let new_root = self.apply_forest_updates(lineage, block_num, entries);

        tracing::debug!(
            target: crate::COMPONENT,
            %account_id,
            %block_num,
            %new_root,
            vault_entries = num_entries,
            "Inserted vault into forest"
        );
        Ok(())
    }

    /// Updates the forest with storage map changes from a delta and returns updated roots.
    ///
    /// Assumes that storage maps for the provided account are not in the forest already.
    fn insert_account_storage(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        storage_delta: &AccountStorageDelta,
    ) {
        for (slot_name, map_delta) in storage_delta.maps() {
            // get the latest root for this map, and make sure the root is for an empty tree
            let prev_root = self.get_latest_storage_map_root(account_id, slot_name);
            assert_eq!(prev_root, Self::empty_smt_root(), "account should not be in the forest");

            let raw_map_entries: Vec<(StorageMapKey, Word)> =
                Vec::from_iter(map_delta.entries().iter().filter_map(|(&key, &value)| {
                    if value == EMPTY_WORD {
                        None
                    } else {
                        Some((key.into_inner(), value))
                    }
                }));

            if raw_map_entries.is_empty() {
                let lineage = Self::storage_lineage_id(account_id, slot_name);
                let _new_root = self.apply_forest_updates(lineage, block_num, Vec::new());

                continue;
            }

            let hashed_entries = Vec::from_iter(
                raw_map_entries.iter().map(|(raw_key, value)| (raw_key.hash().into(), *value)),
            );

            let lineage = Self::storage_lineage_id(account_id, slot_name);
            assert!(self.latest_version(lineage).is_none(), "account should not be in the forest");
            let new_root = self.apply_forest_updates(lineage, block_num, hashed_entries);

            let num_entries = raw_map_entries.len();

            tracing::debug!(
                target: crate::COMPONENT,
                %account_id,
                %block_num,
                ?slot_name,
                %new_root,
                delta_entries = num_entries,
                "Inserted storage map into forest"
            );
        }
    }

    // ASSET VAULT DELTA PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Updates the forest with vault changes from a delta and returns the new root.
    ///
    /// Processes both fungible and non-fungible asset changes, building entries for the vault SMT
    /// and tracking the new root.
    ///
    /// # Arguments
    ///
    /// * `is_full_state` - If `true`, delta values are absolute (new account or DB reconstruction).
    ///   If `false`, delta values are relative changes applied to previous state.
    ///
    /// # Returns
    ///
    /// The new vault root after applying the delta.
    ///
    /// # Errors
    ///
    /// Returns an error if applying a delta results in a negative balance.
    fn update_account_vault(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        vault_delta: &AccountVaultDelta,
    ) -> Result<(), AccountStateForestError> {
        assert!(!vault_delta.is_empty(), "expected the delta not to be empty");

        // get the previous vault root; the root could be for an empty or non-empty SMT
        let lineage = Self::vault_lineage_id(account_id);
        let prev_root = self.latest_root(lineage);

        let mut entries: Vec<(Word, Word)> = Vec::new();

        // Process fungible assets
        for (faucet_id, amount_delta) in vault_delta.fungible().iter() {
            let delta_abs = amount_delta.unsigned_abs();
            let delta = FungibleAsset::new(*faucet_id, delta_abs)?;
            let key = delta.to_key_word();

            let empty = FungibleAsset::new(*faucet_id, 0)?;
            let asset = if let Some(root) = prev_root {
                // Open the proof at the key to get the current value
                let proof = self.forest.open(root, key)?;
                let (_path, leaf) = proof.into_parts();
                let value = leaf.entries().iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
                value
                    .map(|v| FungibleAsset::from_key_value_words(key, v))
                    .transpose()?
                    .unwrap_or(empty)
            } else {
                empty
            };

            let updated = if *amount_delta < 0 {
                asset.sub(delta)?
            } else {
                asset.add(delta)?
            };

            let value = if updated.amount() == 0 {
                EMPTY_WORD
            } else {
                updated.to_value_word()
            };
            entries.push((key, value));
        }

        // Process non-fungible assets
        for (asset, action) in vault_delta.non_fungible().iter() {
            let value = match action {
                NonFungibleDeltaAction::Add => asset.to_value_word(),
                NonFungibleDeltaAction::Remove => EMPTY_WORD,
            };
            entries.push((asset.vault_key().into(), value));
        }

        let vault_entries = entries.len();

        let lineage = Self::vault_lineage_id(account_id);
        let new_root = self.apply_forest_updates(lineage, block_num, entries);

        tracing::debug!(
            target: crate::COMPONENT,
            %account_id,
            %block_num,
            %new_root,
            %vault_entries,
            "Updated vault in forest"
        );
        Ok(())
    }

    // STORAGE MAP DELTA PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Retrieves the most recent storage map SMT root for an account slot.
    fn get_latest_storage_map_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
    ) -> Word {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        self.latest_root(lineage).unwrap_or_else(Self::empty_smt_root)
    }

    /// Updates the forest with storage map changes from a delta.
    ///
    /// # Arguments
    ///
    /// * `is_full_state` - If `true`, delta values are absolute (new account or DB reconstruction).
    ///   If `false`, delta values are relative changes applied to previous state.
    ///
    /// # Returns
    ///
    /// A map from slot name to the new storage map root for that slot.
    fn update_account_storage(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        storage_delta: &AccountStorageDelta,
    ) {
        for (slot_name, map_delta) in storage_delta.maps() {
            // map delta shouldn't be empty, but if it is for some reason, there is nothing to do
            if map_delta.is_empty() {
                continue;
            }

            // update the storage map tree in the forest and add an entry to the storage map roots
            let lineage = Self::storage_lineage_id(account_id, slot_name);
            let delta_entries: Vec<(StorageMapKey, Word)> = Vec::from_iter(
                map_delta.entries().iter().map(|(key, value)| (key.into_inner(), *value)),
            );

            let hashed_entries = Vec::from_iter(
                delta_entries.iter().map(|(raw_key, value)| (raw_key.hash().into(), *value)),
            );

            let new_root = self.apply_forest_updates(lineage, block_num, hashed_entries);

            tracing::debug!(
                target: crate::COMPONENT,
                %account_id,
                %block_num,
                ?slot_name,
                %new_root,
                delta_entries = delta_entries.len(),
                "Updated storage map in forest"
            );
        }
    }

    // PRUNING
    // --------------------------------------------------------------------------------------------

    /// Prunes old entries from the in-memory forest data structures.
    ///
    /// The `LargeSmtForest` itself is truncated to drop historical versions beyond the cutoff.
    ///
    /// Returns the number of pruned roots for observability.
    #[instrument(target = COMPONENT, skip_all, ret, fields(block.number = %chain_tip))]
    pub(crate) fn prune(&mut self, chain_tip: BlockNumber) -> usize {
        let cutoff_block = chain_tip
            .checked_sub(HISTORICAL_BLOCK_RETENTION)
            .unwrap_or(BlockNumber::GENESIS);
        let cutoff_version = cutoff_block.as_u64();

        let mut pruned_count = 0;
        let mut roots_to_prune = Vec::new();

        for versions in self.lineage_versions.values_mut() {
            // Remove all versions strictly before the cutoff, but always keep at least one
            // version (the latest at or before cutoff) so the lineage's current state is
            // preserved.
            let split_idx = versions.partition_point(|(v, _)| *v < cutoff_version);

            // If all versions are before the cutoff, keep the last one as the current state.
            let drain_end = if split_idx >= versions.len() {
                split_idx.saturating_sub(1)
            } else {
                split_idx
            };

            if drain_end > 0 {
                let removed: Vec<_> = versions.drain(..drain_end).collect();
                for (_, root) in &removed {
                    roots_to_prune.push(*root);
                }
                pruned_count += removed.len();
            }
        }

        // Collect all roots still in use across all lineages.
        let active_roots: BTreeSet<Word> = self
            .lineage_versions
            .values()
            .flat_map(|versions| versions.iter().map(|(_, root)| *root))
            .collect();

        // Only pop roots that are no longer referenced by any lineage.
        let orphaned_roots: Vec<Word> =
            roots_to_prune.into_iter().filter(|r| !active_roots.contains(r)).collect();
        self.forest.pop_smts(orphaned_roots);

        pruned_count
    }
}
