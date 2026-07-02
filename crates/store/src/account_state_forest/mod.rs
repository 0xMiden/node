use std::num::NonZeroUsize;

use miden_crypto::hash::rpo::Rpo256;
#[cfg(feature = "rocksdb")]
use miden_crypto::merkle::smt::ForestPersistentBackend;
use miden_crypto::merkle::smt::{Backend, ForestInMemoryBackend};
use miden_node_proto::domain::account::{
    AccountStorageMapDetails,
    AccountVaultDetails,
    StorageMapEntries,
};
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::account::{
    AccountId,
    AccountPatch,
    AccountStoragePatch,
    AccountVaultPatch,
    StorageMapKey,
    StorageMapKeyHash,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetVaultKey, AssetVaultKeyHash};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::smt::{
    ForestOperation,
    LargeSmtForest,
    LargeSmtForestError,
    LineageId,
    RootInfo,
    SMT_DEPTH,
    SmtUpdateBatch,
    TreeId,
};
use miden_protocol::crypto::merkle::{EmptySubtreeRoots, MerkleError};
use miden_protocol::errors::{AssetError, StorageMapError};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{EMPTY_WORD, Word};
use thiserror::Error;

use crate::COMPONENT;
pub use crate::db::models::queries::HISTORICAL_BLOCK_RETENTION;

#[cfg(test)]
mod tests;

const HASHED_STORAGE_MAP_KEY_CACHE_CAPACITY: usize = 65_536;

const HASHED_VAULT_KEY_CACHE_CAPACITY: usize = 65_536;

// ERRORS
// ================================================================================================

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

#[cfg(feature = "rocksdb")]
pub(crate) type AccountStateForestBackend = ForestPersistentBackend;
#[cfg(not(feature = "rocksdb"))]
pub(crate) type AccountStateForestBackend = ForestInMemoryBackend;

const fn empty_smt_root() -> Word {
    *EmptySubtreeRoots::entry(SMT_DEPTH, 0)
}

// ACCOUNT STATE FOREST
// ================================================================================================

/// Result of retrieving storage map details for all entries in a storage map.
#[derive(Debug, PartialEq)]
pub enum AccountStorageMapResult {
    NotFound,
    CannotReconstructKeysFromCache,
    Details(AccountStorageMapDetails),
}

/// Container for forest-related state that needs to be updated atomically.
pub(crate) struct AccountStateForest<B: Backend = ForestInMemoryBackend> {
    /// `LargeSmtForest` for efficient account storage reconstruction. Populated during block import
    /// with storage and vault SMTs.
    forest: LargeSmtForest<B>,

    /// Reverse lookup from hashed SMT storage keys to raw storage map keys.
    storage_map_key_cache: LruCache<StorageMapKeyHash, StorageMapKey>,

    /// Reverse lookup from hashed SMT vault keys to raw vault keys.
    vault_key_cache: LruCache<AssetVaultKeyHash, AssetVaultKey>,
}

#[cfg(test)]
impl AccountStateForest<ForestInMemoryBackend> {
    pub(crate) fn new() -> Self {
        Self {
            forest: Self::create_forest(),
            storage_map_key_cache: LruCache::new(
                NonZeroUsize::new(HASHED_STORAGE_MAP_KEY_CACHE_CAPACITY)
                    .expect("storage map key cache capacity must be non-zero"),
            ),
            vault_key_cache: LruCache::new(
                NonZeroUsize::new(HASHED_VAULT_KEY_CACHE_CAPACITY)
                    .expect("vault key cache capacity must be non-zero"),
            ),
        }
    }

    /// Returns the root of an empty SMT.
    pub(crate) const fn empty_smt_root() -> Word {
        empty_smt_root()
    }

    fn create_forest() -> LargeSmtForest<ForestInMemoryBackend> {
        let backend = ForestInMemoryBackend::new();
        LargeSmtForest::new(backend).expect("in-memory backend should initialize")
    }
}

impl<B: Backend> AccountStateForest<B> {
    pub(crate) fn from_backend(backend: B) -> Result<Self, LargeSmtForestError> {
        Ok(Self {
            forest: LargeSmtForest::new(backend)?,
            storage_map_key_cache: LruCache::new(
                NonZeroUsize::new(HASHED_STORAGE_MAP_KEY_CACHE_CAPACITY)
                    .expect("storage map key cache capacity must be non-zero"),
            ),
            vault_key_cache: LruCache::new(
                NonZeroUsize::new(HASHED_VAULT_KEY_CACHE_CAPACITY)
                    .expect("vault key cache capacity must be non-zero"),
            ),
        })
    }

    #[cfg(feature = "rocksdb")]
    pub(crate) fn lineage_count(&self) -> usize {
        self.forest.lineage_count()
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

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

    fn cache_storage_map_keys_from_patch(&mut self, patch: &AccountPatch) {
        let raw_keys = patch.storage().maps().flat_map(|(_slot_name, map_patch)| {
            map_patch.entries().into_iter().flat_map(|e| e.as_map().keys().copied())
        });
        self.cache_storage_map_keys(raw_keys);
    }

    pub(crate) fn cache_storage_map_keys(&self, raw_keys: impl IntoIterator<Item = StorageMapKey>) {
        self.storage_map_key_cache
            .put_many(raw_keys.into_iter().map(|raw_key| (raw_key.hash(), raw_key)));
    }

    fn cache_vault_keys_from_patch(&mut self, patch: &AccountPatch) {
        self.cache_vault_keys(patch.vault().iter().map(|(vault_key, _)| *vault_key));
    }

    pub(crate) fn cache_vault_keys(&self, raw_keys: impl IntoIterator<Item = AssetVaultKey>) {
        self.vault_key_cache
            .put_many(raw_keys.into_iter().map(|raw_key| (raw_key.hash(), raw_key)));
    }

    #[cfg(test)]
    fn clear_storage_map_key_cache(&self) {
        self.storage_map_key_cache.clear();
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

    // DETAILS
    // --------------------------------------------------------------------------------------------

    /// Enumerates vault contents for the specified account at the requested block.
    ///
    /// Vault keys are hashed before insertion into the SMT, so the forest can only reconstruct the
    /// assets if all hashed keys are known in the reverse-key LRU cache. Returns `Ok(None)` when at
    /// least one raw key is missing from the cache, so the caller should fall back to database
    /// reconstruction.
    #[miden_instrument(
        target = COMPONENT,
        skip_all,
    )]
    pub(crate) fn get_vault_details(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<Option<AccountVaultDetails>, WitnessError> {
        let lineage = Self::vault_lineage_id(account_id);
        let tree = self.get_tree_id(lineage, block_num).ok_or(WitnessError::RootNotFound)?;

        // Return "limit exceeded" if the number of vault entries is above the limit.
        let num_entries =
            self.forest.entry_count(tree).map_err(Self::map_forest_error_to_witness)?;
        if num_entries > AccountVaultDetails::MAX_RETURN_ENTRIES {
            return Ok(Some(AccountVaultDetails::LimitExceeded));
        }

        let entries = self.forest.entries(tree).map_err(Self::map_forest_error_to_witness)?;
        let hashed_entries = entries
            .map(|entry| {
                let entry = entry.map_err(Self::map_forest_error_to_witness)?;
                Ok((AssetVaultKeyHash::from_raw(entry.key), entry.value))
            })
            .collect::<Result<Vec<_>, WitnessError>>()?;

        let raw_keys = self
            .vault_key_cache
            .get_many(hashed_entries.iter().map(|(hashed_key, _)| hashed_key));
        if raw_keys.iter().any(Option::is_none) {
            return Ok(None);
        }

        let assets = raw_keys
            .into_iter()
            .flatten()
            .zip(hashed_entries)
            .map(|(raw_key, (_hashed_key, value))| {
                Asset::from_key_value(raw_key, value).map_err(WitnessError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(AccountVaultDetails::from_assets(assets)))
    }

    /// Opens a storage map and returns storage map details with SMT proofs for the given keys.
    ///
    /// Returns `None` if no storage root is tracked for this account/slot/block combination.
    /// Returns a `MerkleError` if the forest doesn't contain sufficient data for the proofs.
    #[miden_instrument(
        target = COMPONENT,
        skip_all,
    )]
    pub(crate) fn get_storage_map_details_for_keys(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
        raw_keys: &[StorageMapKey],
    ) -> Option<Result<AccountStorageMapDetails, MerkleError>> {
        let lineage = Self::storage_lineage_id(account_id, &slot_name);
        let tree = self.get_tree_id(lineage, block_num)?;

        let proofs = Result::from_iter(raw_keys.iter().map(|raw_key| {
            let key_hashed = raw_key.hash().into();
            self.forest.open(tree, key_hashed).map_err(Self::map_forest_error)
        }));

        Some(proofs.map(|proofs| AccountStorageMapDetails::from_proofs(slot_name, proofs)))
    }

    /// Enumerates a storage map as it is stored in the SMT.
    ///
    /// Storage map keys are hashed before insertion, so returned keys are hashed SMT keys rather
    /// than the raw [`StorageMapKey`] values supplied by users.
    ///
    /// Returns `None` when no storage root is tracked for this account/slot/block combination.
    /// Returns at most `limit` entries.
    fn get_storage_map_entries(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<Result<Vec<(StorageMapKeyHash, Word)>, MerkleError>> {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        let tree = self.get_tree_id(lineage, block_num)?;

        Some(self.forest.entries(tree).map_err(Self::map_forest_error).and_then(|entries| {
            entries
                .map(|entry| {
                    entry
                        .map(|e| (StorageMapKeyHash::from_raw(e.key), e.value))
                        .map_err(Self::map_forest_error)
                })
                .collect()
        }))
    }

    /// Returns the number of storage map entries.
    fn num_storage_map_entries(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<Result<usize, MerkleError>> {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        let tree = self.get_tree_id(lineage, block_num)?;
        Some(self.forest.entry_count(tree).map_err(Self::map_forest_error))
    }

    /// Returns all storage map entries when the forest and reverse-key cache contain enough data.
    ///
    /// Returns `AccountStorageMapResult::NotFound` when no storage root is tracked for this
    /// account/slot/block combination.
    /// Returns `AccountStorageMapResult::CannotReconstructKeysFromCache` when the forest has hashed
    /// entries but at least one raw key is missing from the reverse-key cache, so the caller
    /// should fall back to database reconstruction.
    #[miden_instrument(
        target = COMPONENT,
        skip_all,
    )]
    pub(crate) fn get_storage_map_details_for_all_entries(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
    ) -> Result<AccountStorageMapResult, MerkleError> {
        // Check if number of entries is not larger than the limit.
        let Some(num_entries) =
            self.num_storage_map_entries(account_id, &slot_name, block_num).transpose()?
        else {
            return Ok(AccountStorageMapResult::NotFound);
        };
        if num_entries > AccountStorageMapDetails::MAX_RETURN_ENTRIES {
            return Ok(AccountStorageMapResult::Details(AccountStorageMapDetails {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            }));
        }

        // Fetch (hashed_key, value) pairs.
        let Some(hashed_entries) =
            self.get_storage_map_entries(account_id, &slot_name, block_num).transpose()?
        else {
            return Ok(AccountStorageMapResult::NotFound);
        };

        let raw_keys = self
            .storage_map_key_cache
            .get_many(hashed_entries.iter().map(|(hashed_key, _)| hashed_key));
        if raw_keys.iter().any(Option::is_none) {
            return Ok(AccountStorageMapResult::CannotReconstructKeysFromCache);
        }

        let mut entries = raw_keys
            .into_iter()
            .flatten()
            .zip(hashed_entries)
            .map(|(raw_key, (_hashed_key, value))| (raw_key, value))
            .collect::<Vec<_>>();
        entries.sort_by(|(key_a, _), (key_b, _)| key_a.cmp(key_b));

        Ok(AccountStorageMapResult::Details(AccountStorageMapDetails::from_forest_entries(
            slot_name, entries,
        )))
    }

    // PUBLIC INTERFACE
    // --------------------------------------------------------------------------------------------

    /// Updates the forest with account vault and storage changes from a patch.
    ///
    /// Iterates through account updates and applies each patch to the forest.
    /// Private accounts should be filtered out before calling this method.
    ///
    /// # Arguments
    ///
    /// * `block_num` - Block number for which these updates apply
    /// * `account_updates` - Iterator of `AccountPatch` for public accounts
    #[miden_instrument(
        target = COMPONENT,
        skip_all,
        fields(
            block.number = %block_num,
            num_pruned = tracing::field::Empty,
        ),
    )]
    pub(crate) fn apply_block_updates(
        &mut self,
        block_num: BlockNumber,
        account_updates: impl IntoIterator<Item = AccountPatch>,
    ) {
        for patch in account_updates {
            self.update_account(block_num, &patch);

            tracing::trace!(
                target: crate::LOG_TARGET,
                account_id = %patch.id(),
                %block_num,
                is_full_state = patch.is_full_state(),
                "Updated forest with account patch"
            );
        }

        let number_of_pruned_blocks = self.prune(block_num);
        tracing::Span::current().record("num_pruned", number_of_pruned_blocks);
    }

    /// Updates the forest with account vault and storage changes from a patch.
    ///
    /// Unified interface for updating all account state in the forest, handling both full-state
    /// patches (new accounts or reconstruction from DB) and partial patches (incremental updates
    /// during block application).
    ///
    /// Full-state patches (`patch.is_full_state() == true`) populate the forest from scratch using
    /// an empty SMT root. Partial patches apply changes on top of the previous block's state.
    pub(crate) fn update_account(&mut self, block_num: BlockNumber, patch: &AccountPatch) {
        let account_id = patch.id();
        let is_full_state = patch.is_full_state();

        // Apply vault changes.
        if is_full_state {
            self.insert_account_vault(block_num, account_id, patch.vault());
        } else if !patch.vault().is_empty() {
            self.update_account_vault(block_num, account_id, patch.vault());
        }

        // Apply storage map changes.
        if is_full_state {
            self.insert_account_storage(block_num, account_id, patch.storage());
        } else if !patch.storage().is_empty() {
            self.update_account_storage(block_num, account_id, patch.storage());
        }

        self.cache_storage_map_keys_from_patch(patch);
        self.cache_vault_keys_from_patch(patch);
    }

    // ASSET VAULT DELTA PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Retrieves the most recent vault SMT root for an account. If no vault root is found for the
    /// account, returns an empty SMT root.
    pub(crate) fn get_latest_vault_root(&self, account_id: AccountId) -> Word {
        let lineage = Self::vault_lineage_id(account_id);
        self.forest.latest_root(lineage).unwrap_or_else(empty_smt_root)
    }

    /// Inserts asset vault data into the forest for the specified account. Assumes that asset vault
    /// for this account does not yet exist in the forest.
    ///
    /// # Panics
    /// Panics if the account's vault is already present in the forest.
    fn insert_account_vault(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        vault_patch: &AccountVaultPatch,
    ) {
        let prev_root = self.get_latest_vault_root(account_id);
        let lineage = Self::vault_lineage_id(account_id);
        assert_eq!(prev_root, empty_smt_root(), "account should not be in the forest");
        assert!(
            self.forest.latest_version(lineage).is_none(),
            "account should not be in the forest"
        );

        if vault_patch.is_empty() {
            let lineage = Self::vault_lineage_id(account_id);
            let new_root = self.apply_forest_updates(lineage, block_num, Vec::new());

            tracing::trace!(
                target: crate::LOG_TARGET,
                %account_id,
                %block_num,
                %new_root,
                vault_entries = 0,
                "Inserted vault into forest"
            );
            return;
        }

        let mut entries: Vec<(AssetVaultKey, Word)> = Vec::new();

        for (vault_key, value) in vault_patch.iter() {
            entries.push((*vault_key, *value));
        }

        let num_entries = entries.len();

        let lineage = Self::vault_lineage_id(account_id);
        let operations = Self::build_forest_operations(
            entries.into_iter().map(|(key, value)| (key.hash().as_word(), value)),
        );
        let new_root = self.apply_forest_updates(lineage, block_num, operations);

        tracing::trace!(
            target: crate::LOG_TARGET,
            %account_id,
            %block_num,
            %new_root,
            vault_entries = num_entries,
            "Inserted vault into forest"
        );
    }

    /// Updates the forest with storage map changes from a patch.
    ///
    /// Assumes that storage maps for the provided account are not in the forest already.
    fn insert_account_storage(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        storage_patch: &AccountStoragePatch,
    ) {
        for (slot_name, map_patch) in storage_patch.maps() {
            // get the latest root for this map, and make sure the root is for an empty tree
            let prev_root = self.get_latest_storage_map_root(account_id, slot_name);
            assert_eq!(prev_root, empty_smt_root(), "account should not be in the forest");

            let raw_map_entries: Vec<(StorageMapKey, Word)> = Vec::from_iter(
                map_patch.entries().into_iter().flat_map(|e| e.as_map().iter()).filter_map(
                    |(&key, &value)| if value == EMPTY_WORD { None } else { Some((key, value)) },
                ),
            );

            if raw_map_entries.is_empty() {
                let lineage = Self::storage_lineage_id(account_id, slot_name);
                let _new_root = self.apply_forest_updates(lineage, block_num, Vec::new());

                continue;
            }

            let hashed_entries = Vec::from_iter(
                raw_map_entries.iter().map(|(raw_key, value)| (raw_key.hash().into(), *value)),
            );

            let lineage = Self::storage_lineage_id(account_id, slot_name);
            assert!(
                self.forest.latest_version(lineage).is_none(),
                "account should not be in the forest"
            );
            let operations = Self::build_forest_operations(hashed_entries);
            let new_root = self.apply_forest_updates(lineage, block_num, operations);

            let num_entries = raw_map_entries.len();

            tracing::trace!(
                target: crate::LOG_TARGET,
                %account_id,
                %block_num,
                ?slot_name,
                %new_root,
                patch_entries = num_entries,
                "Inserted storage map into forest"
            );
        }
    }

    // ASSET VAULT PATCH PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Updates the forest with the account's vault changes from the patch.
    ///
    /// Writes the patch's absolute vault entries to the vault SMT, where an empty value removes the
    /// corresponding asset.
    ///
    /// # Panics
    /// Panics if the provided vault patch is empty.
    fn update_account_vault(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        vault_patch: &AccountVaultPatch,
    ) {
        assert!(!vault_patch.is_empty(), "expected the patch not to be empty");

        let mut entries: Vec<(AssetVaultKey, Word)> = Vec::new();

        for (vault_key, value) in vault_patch.iter() {
            entries.push((*vault_key, *value));
        }

        let vault_entries = entries.len();

        let lineage = Self::vault_lineage_id(account_id);
        let operations = Self::build_forest_operations(
            entries.into_iter().map(|(key, value)| (key.hash().as_word(), value)),
        );
        let new_root = self.apply_forest_updates(lineage, block_num, operations);

        tracing::trace!(
            target: crate::LOG_TARGET,
            %account_id,
            %block_num,
            %new_root,
            %vault_entries,
            "Updated vault in forest"
        );
    }

    // STORAGE MAP DELTA PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Retrieves the most recent storage map SMT root for an account slot.
    pub(crate) fn get_latest_storage_map_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
    ) -> Word {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        self.forest.latest_root(lineage).unwrap_or_else(empty_smt_root)
    }

    /// Updates the forest with storage map changes from a patch.
    ///
    /// # Returns
    ///
    /// A map from slot name to the new storage map root for that slot.
    fn update_account_storage(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        storage_patch: &AccountStoragePatch,
    ) {
        for (slot_name, map_patch) in storage_patch.maps() {
            // map patch shouldn't be empty, but if it is for some reason, there is nothing to do
            let Some(entries) = map_patch.entries() else {
                continue;
            };
            if entries.is_empty() {
                continue;
            }

            // update the storage map tree in the forest and add an entry to the storage map roots
            let lineage = Self::storage_lineage_id(account_id, slot_name);
            let patch_entries: Vec<(StorageMapKey, Word)> =
                Vec::from_iter(entries.as_map().iter().map(|(key, value)| (*key, *value)));

            let hashed_entries = Vec::from_iter(
                patch_entries.iter().map(|(raw_key, value)| (raw_key.hash().into(), *value)),
            );

            let operations = Self::build_forest_operations(hashed_entries);
            let new_root = self.apply_forest_updates(lineage, block_num, operations);

            tracing::trace!(
                target: crate::LOG_TARGET,
                %account_id,
                %block_num,
                ?slot_name,
                %new_root,
                patch_entries = patch_entries.len(),
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
    pub(crate) fn prune(&mut self, chain_tip: BlockNumber) -> usize {
        let cutoff_block = chain_tip
            .checked_sub(HISTORICAL_BLOCK_RETENTION)
            .unwrap_or(BlockNumber::GENESIS);
        let before = self.forest.roots().count();

        self.forest.truncate(cutoff_block.as_u64());

        let after = self.forest.roots().count();
        before.saturating_sub(after)
    }
}
