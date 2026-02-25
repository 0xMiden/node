use std::collections::BTreeSet;

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::merkle::smt::{
    ForestInMemoryBackend,
    ForestOperation,
    LargeSmtForest,
    LargeSmtForestError,
    LineageId,
    RootInfo,
    SMT_DEPTH,
    SmtUpdateBatch,
    TreeId,
};
use miden_crypto::merkle::{EmptySubtreeRoots, MerkleError};
use miden_node_proto::domain::account::AccountStorageMapDetails;
use miden_node_utils::ErrorReport;
use miden_protocol::account::delta::{AccountDelta, AccountStorageDelta, AccountVaultDelta};
use miden_protocol::account::{
    AccountId,
    NonFungibleDeltaAction,
    StorageMap,
    StorageMapWitness,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetVaultKey, AssetWitness, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::{AssetError, StorageMapError};
use miden_protocol::utils::Serializable;
use miden_protocol::{EMPTY_WORD, Word};
use thiserror::Error;
use tracing::instrument;

use crate::COMPONENT;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Number of historical blocks to retain in the in-memory forest.
/// Entries older than `chain_tip - HISTORICAL_BLOCK_RETENTION` will be pruned.
pub const HISTORICAL_BLOCK_RETENTION: u32 = 50;

// ERRORS
// ================================================================================================

#[derive(Debug, Error)]
pub enum InnerForestError {
    #[error(transparent)]
    Asset(#[source] AssetError),
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

// INNER FOREST
// ================================================================================================

/// Container for forest-related state that needs to be updated atomically.
pub(crate) struct InnerForest {
    /// `LargeSmtForest` for efficient account storage reconstruction.
    /// Populated during block import with storage and vault SMTs.
    forest: LargeSmtForest<ForestInMemoryBackend>,
}

impl InnerForest {
    pub(crate) fn new() -> Self {
        Self { forest: Self::create_forest() }
    }

    fn create_forest() -> LargeSmtForest<ForestInMemoryBackend> {
        let backend = ForestInMemoryBackend::new();
        LargeSmtForest::new(backend).expect("in-memory backend should initialize")
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
    ) -> TreeId {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        self.lookup_tree_id(lineage, block_num)
    }

    #[cfg(test)]
    fn tree_id_for_vault_root(&self, account_id: AccountId, block_num: BlockNumber) -> TreeId {
        let lineage = Self::vault_lineage_id(account_id);
        self.lookup_tree_id(lineage, block_num)
    }

    #[expect(clippy::unused_self)]
    fn lookup_tree_id(&self, lineage: LineageId, block_num: BlockNumber) -> TreeId {
        TreeId::new(lineage, block_num.as_u64())
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

    fn build_forest_operations(
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Vec<ForestOperation> {
        entries
            .into_iter()
            .map(|(key, value)| {
                if value == EMPTY_WORD {
                    ForestOperation::remove(key)
                } else {
                    ForestOperation::insert(key, value)
                }
            })
            .collect()
    }

    fn apply_forest_updates(
        &mut self,
        lineage: LineageId,
        block_num: BlockNumber,
        operations: Vec<ForestOperation>,
    ) -> Word {
        let updates = if operations.is_empty() {
            SmtUpdateBatch::empty()
        } else {
            SmtUpdateBatch::new(operations.into_iter())
        };
        let version = block_num.as_u64();
        let tree = if self.forest.latest_version(lineage).is_some() {
            self.forest
                .update_tree(lineage, version, updates)
                .expect("forest update should succeed")
        } else {
            self.forest
                .add_lineage(lineage, version, updates)
                .expect("forest update should succeed")
        };
        tree.root()
    }

    fn map_forest_error(error: LargeSmtForestError) -> MerkleError {
        match error {
            LargeSmtForestError::Merkle(merkle) => merkle,
            other => MerkleError::InternalError(other.as_report()),
        }
    }

    fn map_forest_error_to_witness(error: LargeSmtForestError) -> WitnessError {
        match error {
            LargeSmtForestError::Merkle(merkle) => WitnessError::MerkleError(merkle),
            other => WitnessError::MerkleError(MerkleError::InternalError(other.as_report())),
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    fn get_tree_id(&self, lineage: LineageId, block_num: BlockNumber) -> Option<TreeId> {
        let tree = self.lookup_tree_id(lineage, block_num);
        match self.forest.root_info(tree) {
            RootInfo::LatestVersion(_) | RootInfo::HistoricalVersion(_) => Some(tree),
            RootInfo::Missing => {
                let latest_version = self.forest.latest_version(lineage)?;
                if latest_version <= block_num.as_u64() {
                    Some(TreeId::new(lineage, latest_version))
                } else {
                    None
                }
            },
        }
    }

    #[cfg(test)]
    fn get_tree_root(&self, lineage: LineageId, block_num: BlockNumber) -> Option<Word> {
        let tree = self.get_tree_id(lineage, block_num)?;
        match self.forest.root_info(tree) {
            RootInfo::LatestVersion(root) | RootInfo::HistoricalVersion(root) => Some(root),
            RootInfo::Missing => None,
        }
    }

    /// Retrieves a vault root for the specified account and block.
    #[cfg(test)]
    pub(crate) fn get_vault_root(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Option<Word> {
        let lineage = Self::vault_lineage_id(account_id);
        self.get_tree_root(lineage, block_num)
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
        self.get_tree_root(lineage, block_num)
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
        raw_key: Word,
    ) -> Result<StorageMapWitness, WitnessError> {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        let tree = self.get_tree_id(lineage, block_num).ok_or(WitnessError::RootNotFound)?;
        let key = StorageMap::hash_key(raw_key);
        let proof = self.forest.open(tree, key).map_err(Self::map_forest_error_to_witness)?;

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
        let tree = self.get_tree_id(lineage, block_num).ok_or(WitnessError::RootNotFound)?;
        let witnessees: Result<Vec<_>, WitnessError> =
            Result::from_iter(asset_keys.into_iter().map(|key| {
                let proof = self
                    .forest
                    .open(tree, key.into())
                    .map_err(Self::map_forest_error_to_witness)?;
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
        raw_keys: &[Word],
    ) -> Option<Result<AccountStorageMapDetails, MerkleError>> {
        let lineage = Self::storage_lineage_id(account_id, &slot_name);
        let tree = self.get_tree_id(lineage, block_num)?;

        let proofs = Result::from_iter(raw_keys.iter().map(|raw_key| {
            let key = StorageMap::hash_key(*raw_key);
            self.forest.open(tree, key).map_err(Self::map_forest_error)
        }));

        Some(proofs.map(|proofs| AccountStorageMapDetails::from_proofs(slot_name, proofs)))
    }

    // PUBLIC INTERFACE
    // --------------------------------------------------------------------------------------------

    /// Applies account updates from a block to the forest.
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
    ) -> Result<(), InnerForestError> {
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
    ) -> Result<(), InnerForestError> {
        let account_id = delta.id();
        let is_full_state = delta.is_full_state();

        if is_full_state {
            self.insert_account_vault(block_num, account_id, delta.vault());
        } else if !delta.vault().is_empty() {
            self.update_account_vault(block_num, account_id, delta.vault())?;
        }

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
        self.forest.latest_root(lineage).unwrap_or_else(Self::empty_smt_root)
    }

    /// Inserts asset vault data into the forest for the specified account. Assumes that asset
    /// vault for this account does not yet exist in the forest.
    fn insert_account_vault(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        delta: &AccountVaultDelta,
    ) {
        // get the current vault root for the account, and make sure it is empty
        let prev_root = self.get_latest_vault_root(account_id);
        let lineage = Self::vault_lineage_id(account_id);
        assert_eq!(prev_root, Self::empty_smt_root(), "account should not be in the forest");
        assert!(
            self.forest.latest_version(lineage).is_none(),
            "account should not be in the forest"
        );

        if delta.is_empty() {
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
            return;
        }

        let mut entries: Vec<(Word, Word)> = Vec::new();

        // process fungible assets
        for (faucet_id, amount_delta) in delta.fungible().iter() {
            let amount =
                (*amount_delta).try_into().expect("full-state amount should be non-negative");
            let asset = FungibleAsset::new(*faucet_id, amount).expect("valid faucet id");
            entries.push((asset.vault_key().into(), asset.into()));
        }

        // process non-fungible assets
        for (&asset, _action) in delta.non_fungible().iter() {
            let asset_vault_key = asset.vault_key().into();
            match _action {
                NonFungibleDeltaAction::Add => entries.push((asset_vault_key, asset.into())),
                NonFungibleDeltaAction::Remove => entries.push((asset_vault_key, EMPTY_WORD)),
            }
        }

        assert!(!entries.is_empty(), "non-empty delta should contain entries");
        let num_entries = entries.len();

        let lineage = Self::vault_lineage_id(account_id);
        let operations = Self::build_forest_operations(entries);
        let _new_root = self.apply_forest_updates(lineage, block_num, operations);

        tracing::debug!(
            target: crate::COMPONENT,
            %account_id,
            %block_num,
            vault_entries = num_entries,
            "Inserted vault into forest"
        );
    }

    /// Updates the forest with vault changes from a delta. The vault delta is assumed to be
    /// non-empty.
    ///
    /// Processes both fungible and non-fungible asset changes, building entries for the vault SMT
    /// and tracking the new root.
    ///
    /// # Errors
    ///
    /// Returns an error if applying a delta results in a negative balance.
    fn update_account_vault(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        delta: &AccountVaultDelta,
    ) -> Result<(), InnerForestError> {
        assert!(!delta.is_empty(), "expected the delta not to be empty");

        // get the previous vault root; the root could be for an empty or non-empty SMT
        let lineage = Self::vault_lineage_id(account_id);
        let prev_tree =
            self.forest.latest_version(lineage).map(|version| TreeId::new(lineage, version));

        let mut entries: Vec<(Word, Word)> = Vec::new();

        // Process fungible assets
        for (faucet_id, amount_delta) in delta.fungible().iter() {
            let delta = FungibleAsset::new(*faucet_id, *amount_delta)?;
            let key: Word = delta.expect("valid faucet id").vault_key().into();

            let empty = FungibleAsset::new(*faucet_id, 0)?;
            let mut asset = if let Some(prev_tree) = prev_tree {
                self.forest
                    .get(tree, key)?
                    .map(|asset_key| FungibleAsset::try_from(asset_key))
                    .transpose()?
                    .unwrap_or_else(|| empty)
            } else {
                empty
            };

            let updated = asset.add(delta).map_err(InnerForestError::Asset)?;

            let value = if updated.amount() == 0 {
                EMPTY_WORD
            } else {
                Word::from(updated)
            };
            entries.push((key, value));
        }

        // Process non-fungible assets
        for (asset, action) in delta.non_fungible().iter() {
            let value = match action {
                NonFungibleDeltaAction::Add => Word::from(Asset::NonFungible(*asset)),
                NonFungibleDeltaAction::Remove => EMPTY_WORD,
            };
            entries.push((asset.vault_key().into(), value));
        }

        let vault_entries = entries.len();

        let lineage = Self::vault_lineage_id(account_id);
        let operations = Self::build_forest_operations(entries);
        let new_root = self.apply_forest_updates(lineage, block_num, operations);

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

    /// Retrieves the most recent storage map SMT root for an account slot. If no storage root is
    /// found for the slot, returns an empty SMT root.
    fn get_latest_storage_map_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
    ) -> Word {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        self.forest.latest_root(lineage).map_or_else(Self::empty_smt_root, |root| root)
    }

    /// Inserts all storage maps from the provided storage delta into the forest.
    ///
    /// Assumes that storage maps for the provided account are not in the forest already.
    fn insert_account_storage(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        delta: &AccountStorageDelta,
    ) {
        for (slot_name, map_delta) in delta.maps() {
            // get the latest root for this map, and make sure the root is for an empty tree
            let prev_root = self.get_latest_storage_map_root(account_id, slot_name);
            assert_eq!(prev_root, Self::empty_smt_root(), "account should not be in the forest");

            // build a vector of raw entries and filter out any empty values; such values
            // shouldn't be present in full-state deltas, but it is good to exclude them
            // explicitly
            let raw_map_entries: Vec<(Word, Word)> =
                Vec::from_iter(map_delta.entries().iter().filter_map(|(&key, &value)| {
                    if value == EMPTY_WORD {
                        None
                    } else {
                        Some((Word::from(key), value))
                    }
                }));

            if raw_map_entries.is_empty() {
                let lineage = Self::storage_lineage_id(account_id, slot_name);
                let _new_root = self.apply_forest_updates(lineage, block_num, Vec::new());

                continue;
            }

            let hashed_entries = Vec::from_iter(
                raw_map_entries
                    .iter()
                    .map(|(raw_key, value)| (StorageMap::hash_key(*raw_key), *value)),
            );

            let lineage = Self::storage_lineage_id(account_id, slot_name);
            assert!(
                self.forest.latest_version(lineage).is_none(),
                "account should not be in the forest"
            );
            let operations = Self::build_forest_operations(hashed_entries);
            let _new_root = self.apply_forest_updates(lineage, block_num, operations);

            let num_entries = raw_map_entries.len();

            tracing::debug!(
                target: crate::COMPONENT,
                %account_id,
                %block_num,
                ?slot_name,
                delta_entries = num_entries,
                "Inserted storage map into forest"
            );
        }
    }

    /// Updates the forest with storage map changes from a delta.
    ///
    /// Processes storage map slot deltas, building SMTs for each modified slot and tracking the
    /// new roots and accumulated entries.
    fn update_account_storage(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        delta: &AccountStorageDelta,
    ) {
        for (slot_name, map_delta) in delta.maps() {
            // map delta shouldn't be empty, but if it is for some reason, there is nothing to do
            if map_delta.is_empty() {
                continue;
            }

            // update the storage map tree in the forest and add an entry to the storage map roots
            let lineage = Self::storage_lineage_id(account_id, slot_name);
            let delta_entries: Vec<(Word, Word)> = Vec::from_iter(
                map_delta.entries().iter().map(|(key, value)| ((*key).into(), *value)),
            );

            let hashed_entries = Vec::from_iter(
                delta_entries
                    .iter()
                    .map(|(raw_key, value)| (StorageMap::hash_key(*raw_key), *value)),
            );

            let operations = Self::build_forest_operations(hashed_entries);
            let _new_root = self.apply_forest_updates(lineage, block_num, operations);

            tracing::debug!(
                target: crate::COMPONENT,
                %account_id,
                %block_num,
                ?slot_name,
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
    #[instrument(target = COMPONENT, skip_all, fields(block.number = %chain_tip))]
    pub(crate) fn prune(&mut self, chain_tip: BlockNumber) -> usize {
        let cutoff_block =
            BlockNumber::from(chain_tip.as_u32().saturating_sub(HISTORICAL_BLOCK_RETENTION));
        let before = self.forest.roots().count();

        self.forest.truncate(cutoff_block.as_u64());

        let after = self.forest.roots().count();
        before.saturating_sub(after)
    }
}
