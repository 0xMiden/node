use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use miden_crypto::hash::rpo::Rpo256;
#[cfg(feature = "rocksdb")]
use miden_crypto::merkle::smt::ForestPersistentBackend;
use miden_crypto::merkle::smt::{Backend, BackendReader, ForestInMemoryBackend};
use miden_node_proto::domain::account::{
    AccountStorageMapDetails,
    AccountVaultDetails,
    StorageMapEntries,
};
use miden_node_tracing::{ErrorReport, miden_instrument, trace};
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::account::{
    AccountId,
    AccountPatch,
    StorageMapKey,
    StorageMapKeyHash,
    StoragePatchOperation,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetId, AssetIdHash};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::smt::{
    LargeSmtForest,
    LargeSmtForestError,
    LineageId,
    RootInfo,
    SMT_DEPTH,
    SmtForestMutationSet,
    SmtForestOperation,
    SmtForestUpdateBatch,
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
use crate::db::models::queries::{PrecomputedPublicAccountState, PrecomputedPublicAccountStates};
use crate::errors::AccountStateForestUpdateError;

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

/// The read-only snapshot backend for the forest, used by in-memory state snapshots.
pub(crate) type AccountStateForestBackendReader = <AccountStateForestBackend as Backend>::Reader;

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
pub(crate) struct AccountStateForest<B: BackendReader = ForestInMemoryBackend> {
    /// `LargeSmtForest` for efficient account storage reconstruction. Populated during block import
    /// with storage and vault SMTs.
    forest: LargeSmtForest<B>,

    /// Reverse lookup from hashed SMT storage keys to raw storage map keys.
    storage_map_key_cache: LruCache<StorageMapKeyHash, StorageMapKey>,

    /// Reverse lookup from hashed SMT vault keys to raw vault keys.
    pub(crate) vault_key_cache: LruCache<AssetIdHash, AssetId>,
}

/// Account-state forest mutations and roots prepared against one forest snapshot.
///
/// The update is bound to the `block_num` passed to
/// [`AccountStateForest::compute_block_update_mutations`] and to the forest lineage versions and
/// roots observed by that call. It must be applied exactly once, to the same forest, without an
/// intervening mutation. The type is consumed on application to prevent accidental reuse.
pub(crate) struct PreparedAccountStateForestBlockUpdate<B: Backend = ForestInMemoryBackend> {
    /// Roots derived from `mutations` for persistence alongside the corresponding block.
    pub(crate) account_states: PrecomputedPublicAccountStates,
    /// Snapshot-bound forest mutations that produce `account_states`.
    mutations: SmtForestMutationSet<B>,
    /// Patches retained to update raw-key caches after the forest mutation succeeds.
    account_patches: Vec<AccountPatch>,
}

/// Forest lineages updated by each account patch in a prepared block update.
///
/// This mapping associates roots from the forest mutation set with account vaults and named
/// storage-map slots when building the precomputed state passed to SQLite.
#[derive(Default)]
struct AccountUpdateForestLineages {
    vault: BTreeMap<AccountId, LineageId>,
    storage: BTreeMap<AccountId, BTreeMap<StorageSlotName, LineageId>>,
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

impl<B: BackendReader> AccountStateForest<B> {
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
    ) -> Vec<SmtForestOperation> {
        entries
            .into_iter()
            .map(|(key, value)| {
                if value == EMPTY_WORD {
                    SmtForestOperation::remove(key)
                } else {
                    SmtForestOperation::insert(key, value)
                }
            })
            .collect()
    }

    fn update_batch_from_operations(operations: Vec<SmtForestOperation>) -> SmtUpdateBatch {
        if operations.is_empty() {
            SmtUpdateBatch::empty()
        } else {
            SmtUpdateBatch::new(operations.into_iter())
        }
    }

    /// Builds the leaf removals needed to replace a storage-map lineage with an empty tree.
    ///
    /// `LargeSmtForest` has no lineage reset operation. This operation enumerates the latest tree
    /// and costs O(n) in its number of entries. A removed map remains the latest version of its
    /// lineage until code recreates it. Pruning cannot discard the latest version. The
    /// `account_state_forest` benchmark measures the recreation cost.
    fn build_current_tree_removal_operations(
        &self,
        lineage: LineageId,
    ) -> Result<Vec<SmtForestOperation>, LargeSmtForestError> {
        let Some(version) = self.forest.latest_version(lineage) else {
            return Ok(Vec::new());
        };

        let tree = TreeId::new(lineage, version);
        self.forest
            .entries(tree)?
            .map(|entry| entry.map(|entry| SmtForestOperation::remove(entry.key)))
            .collect()
    }

    /// Adds the vault operations from `patch` to a prepared forest update batch.
    ///
    /// Full-state patches always create a vault lineage, including for an empty vault. Partial
    /// patches with no vault changes are skipped. Updated lineages are recorded so their computed
    /// roots can later be associated with the account.
    ///
    /// # Errors
    ///
    /// Returns an error if a full-state patch targets an existing vault lineage.
    fn add_vault_updates(
        &self,
        batch: &mut SmtForestUpdateBatch,
        lineages: &mut AccountUpdateForestLineages,
        patch: &AccountPatch,
    ) -> Result<(), AccountStateForestUpdateError> {
        let account_id = patch.id();
        if !patch.is_full_state() && patch.vault().is_empty() {
            return Ok(());
        }

        let lineage = Self::vault_lineage_id(account_id);
        if patch.is_full_state() && self.forest.latest_version(lineage).is_some() {
            return Err(AccountStateForestUpdateError::VaultLineageAlreadyExists { account_id });
        }

        let operations = Self::build_forest_operations(
            patch.vault().iter().map(|(key, value)| (key.hash().as_word(), *value)),
        );
        let updates = Self::update_batch_from_operations(operations);
        batch.operations(lineage).add_operations(updates.into_iter());
        lineages.vault.insert(account_id, lineage);
        Ok(())
    }

    /// Adds storage-map lineage creation operations for a full-state account patch.
    ///
    /// Empty-word entries are omitted from the new map state. Every map lineage is recorded,
    /// including empty maps, so its computed root can be passed to SQLite.
    ///
    /// # Errors
    ///
    /// Returns an error if any storage-map lineage for the account already exists.
    fn add_full_state_storage_updates(
        &self,
        batch: &mut SmtForestUpdateBatch,
        lineages: &mut AccountUpdateForestLineages,
        patch: &AccountPatch,
    ) -> Result<(), AccountStateForestUpdateError> {
        let account_id = patch.id();
        for (slot_name, map_patch) in patch.storage().maps() {
            let raw_map_entries = map_patch
                .entries()
                .into_iter()
                .flat_map(|entries| entries.as_map().iter())
                .filter_map(
                    |(&key, &value)| {
                        if value == EMPTY_WORD { None } else { Some((key, value)) }
                    },
                )
                .collect::<Vec<_>>();
            let operations = Self::build_forest_operations(
                raw_map_entries.iter().map(|(raw_key, value)| (raw_key.hash().into(), *value)),
            );
            let lineage = Self::storage_lineage_id(account_id, slot_name);
            if self.forest.latest_version(lineage).is_some() {
                return Err(AccountStateForestUpdateError::StorageLineageAlreadyExists {
                    account_id,
                    slot_name: slot_name.clone(),
                });
            }

            let updates = Self::update_batch_from_operations(operations);
            batch.operations(lineage).add_operations(updates.into_iter());
            lineages
                .storage
                .entry(account_id)
                .or_default()
                .insert(slot_name.clone(), lineage);
        }
        Ok(())
    }

    /// Adds storage-map operations from a partial account patch to a prepared update batch.
    ///
    /// Updates are applied incrementally. A `Create` replaces an existing lineage by first removing
    /// its current leaves, while a `Remove` only removes the slot from the account storage header and
    /// leaves its forest lineage available for historical queries. No-op updates are skipped, but an
    /// empty `Create` still creates a lineage and records its root.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the current lineage while preparing a replacement fails.
    fn add_partial_storage_updates(
        &self,
        batch: &mut SmtForestUpdateBatch,
        lineages: &mut AccountUpdateForestLineages,
        patch: &AccountPatch,
    ) -> Result<(), LargeSmtForestError> {
        if patch.storage().is_empty() {
            return Ok(());
        }

        let account_id = patch.id();
        for (slot_name, map_patch) in patch.storage().maps() {
            let lineage = Self::storage_lineage_id(account_id, slot_name);
            let Some(entries) = map_patch.entries() else {
                // Removing the slot from the account storage header makes this lineage
                // inaccessible. The forest has no lineage reset primitive, so keep it unchanged for
                // historical queries. This retains the latest tree indefinitely; a later Create
                // replaces it by enumerating and removing its leaves.
                continue;
            };
            if entries.is_empty() && map_patch.patch_op() != StoragePatchOperation::Create {
                continue;
            }

            let mut operations = if map_patch.patch_op() == StoragePatchOperation::Create {
                self.build_current_tree_removal_operations(lineage)?
            } else {
                Vec::new()
            };
            operations.extend(Self::build_forest_operations(
                entries.as_map().iter().map(|(key, value)| (key.hash().into(), *value)),
            ));

            if operations.is_empty() && self.forest.latest_version(lineage).is_none() {
                // An empty Create still needs an empty lineage and its root.
                if map_patch.patch_op() != StoragePatchOperation::Create {
                    continue;
                }
            }

            let updates = Self::update_batch_from_operations(operations);
            batch.operations(lineage).add_operations(updates.into_iter());
            lineages
                .storage
                .entry(account_id)
                .or_default()
                .insert(slot_name.clone(), lineage);
        }

        Ok(())
    }

    /// Builds the forest update batch and lineage lookup for a collection of account patches.
    ///
    /// This method does not mutate the forest. The returned lineage lookup identifies the vault and
    /// storage-map roots that must be extracted after the batch mutations are computed.
    ///
    /// # Errors
    ///
    /// Returns an error if a full-state patch targets an existing lineage or a partial storage-map
    /// replacement cannot be prepared.
    fn prepare_block_update_batch(
        &self,
        account_patches: &[AccountPatch],
    ) -> Result<(SmtForestUpdateBatch, AccountUpdateForestLineages), AccountStateForestUpdateError>
    {
        let mut batch = SmtForestUpdateBatch::empty();
        let mut lineages = AccountUpdateForestLineages::default();

        for patch in account_patches {
            self.add_vault_updates(&mut batch, &mut lineages, patch)?;
            if patch.is_full_state() {
                self.add_full_state_storage_updates(&mut batch, &mut lineages, patch)?;
            } else {
                self.add_partial_storage_updates(&mut batch, &mut lineages, patch)?;
            }
        }

        Ok((batch, lineages))
    }

    /// Associates roots from a computed forest mutation set with their public accounts.
    ///
    /// Each result contains the account's final vault root and roots only for storage maps mutated
    /// by the corresponding patch. An unchanged vault uses its current forest root.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutation set is missing a root for a lineage recorded while building
    /// the update batch.
    fn precomputed_account_states_from_mutations<B2: Backend>(
        &self,
        account_patches: &[AccountPatch],
        lineages: &AccountUpdateForestLineages,
        mutations: &SmtForestMutationSet<B2>,
    ) -> Result<PrecomputedPublicAccountStates, AccountStateForestUpdateError> {
        let mut account_states = PrecomputedPublicAccountStates::new();
        let roots = mutations
            .roots()
            .map(|root| (root.lineage(), root.root()))
            .collect::<BTreeMap<_, _>>();

        for patch in account_patches {
            let account_id = patch.id();
            let vault_root = match lineages.vault.get(&account_id) {
                Some(lineage) => roots.get(lineage).copied().ok_or(
                    AccountStateForestUpdateError::MissingComputedRoot { lineage: *lineage },
                )?,
                None => self.get_latest_vault_root(account_id),
            };
            let mut storage_map_roots = BTreeMap::new();
            if let Some(account_lineages) = lineages.storage.get(&account_id) {
                for (slot_name, lineage) in account_lineages {
                    let root = roots.get(lineage).copied().ok_or(
                        AccountStateForestUpdateError::MissingComputedRoot { lineage: *lineage },
                    )?;
                    storage_map_roots.insert(slot_name.clone(), root);
                }
            }

            account_states.insert(
                account_id,
                PrecomputedPublicAccountState { vault_root, storage_map_roots },
            );
        }

        Ok(account_states)
    }

    fn cache_hashed_keys_from_patch(&mut self, patch: &AccountPatch) {
        let raw_keys = patch.storage().maps().flat_map(|(_slot_name, map_patch)| {
            map_patch.entries().into_iter().flat_map(|e| e.as_map().keys().copied())
        });
        self.cache_storage_map_keys(raw_keys);

        let raw_keys = patch.vault().iter().map(|(vault_key, _)| *vault_key);
        self.vault_key_cache
            .put_many(raw_keys.into_iter().map(|raw_key| (raw_key.hash(), raw_key)));
    }

    pub(crate) fn cache_storage_map_keys(&self, raw_keys: impl IntoIterator<Item = StorageMapKey>) {
        self.storage_map_key_cache
            .put_many(raw_keys.into_iter().map(|raw_key| (raw_key.hash(), raw_key)));
    }

    #[cfg(test)]
    fn clear_storage_map_key_cache(&self) {
        self.storage_map_key_cache.clear();
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
                Ok((AssetIdHash::from_raw(entry.key), entry.value))
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
                Asset::new(raw_key, value).map_err(WitnessError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(AccountVaultDetails::from_assets(assets)))
    }

    /// Opens a storage map and returns one partial SMT covering the requested keys.
    ///
    /// Returns `None` if no storage root is tracked for this account/slot/block combination.
    /// Returns a `MerkleError` if the forest doesn't contain sufficient data for the proofs.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub(crate) fn get_storage_map_details_for_keys(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
        raw_keys: Vec<StorageMapKey>,
    ) -> Option<Result<AccountStorageMapDetails, MerkleError>> {
        let lineage = Self::storage_lineage_id(account_id, &slot_name);
        let tree = self.get_tree_id(lineage, block_num)?;
        let map_root = match self.forest.root_info(tree) {
            RootInfo::LatestVersion(root) | RootInfo::HistoricalVersion(root) => root,
            RootInfo::Missing => return None,
        };

        let proofs = raw_keys
            .iter()
            .map(|raw_key| {
                let key_hashed = raw_key.hash().into();
                self.forest.open(tree, key_hashed).map_err(Self::map_forest_error)
            })
            .collect::<Result<_, _>>();

        Some(proofs.and_then(|proofs| {
            AccountStorageMapDetails::from_proofs(slot_name, map_root, raw_keys, proofs)
        }))
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
        entries.sort_by_key(|(key, _)| *key);

        Ok(AccountStorageMapResult::Details(AccountStorageMapDetails::from_forest_entries(
            slot_name, entries,
        )))
    }

    /// Retrieves the most recent vault SMT root for an account. If no vault root is found for the
    /// account, returns an empty SMT root.
    pub(crate) fn get_latest_vault_root(&self, account_id: AccountId) -> Word {
        let lineage = Self::vault_lineage_id(account_id);
        self.forest.latest_root(lineage).unwrap_or_else(empty_smt_root)
    }

    /// Retrieves the most recent storage map SMT root for an account slot.
    pub(crate) fn get_latest_storage_map_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
    ) -> Word {
        let lineage = Self::storage_lineage_id(account_id, slot_name);
        self.forest.latest_root(lineage).unwrap_or_else(empty_smt_root)
    }
}

impl<B: Backend> AccountStateForest<B> {
    /// Returns a read-only snapshot of this forest backed by a reader view of the backend.
    ///
    /// The reverse-key caches are shallow clones sharing the same underlying storage, so cache
    /// entries added by the writer are visible to snapshot readers and vice versa.
    pub(crate) fn reader(&self) -> Result<AccountStateForest<B::Reader>, LargeSmtForestError> {
        Ok(AccountStateForest {
            forest: self.forest.reader()?,
            storage_map_key_cache: self.storage_map_key_cache.clone(),
            vault_key_cache: self.vault_key_cache.clone(),
        })
    }

    // PUBLIC INTERFACE
    // --------------------------------------------------------------------------------------------

    /// Prepares an account-state forest update without mutating the forest.
    ///
    /// The returned update is tied to `block_num` and the forest's current lineage versions and
    /// roots. It must be passed exactly once to [`Self::apply_precomputed_block_update`] with the
    /// same `block_num`, before any intervening forest mutation. Its precomputed account roots must
    /// only be persisted as part of committing that same block.
    ///
    /// # Errors
    ///
    /// Returns an error when a full-state patch targets an existing lineage, a computed lineage
    /// root is missing, or the forest backend cannot prepare the mutation set.
    pub(crate) fn compute_block_update_mutations(
        &self,
        block_num: BlockNumber,
        account_updates: impl IntoIterator<Item = AccountPatch>,
    ) -> Result<PreparedAccountStateForestBlockUpdate<B>, AccountStateForestUpdateError> {
        let account_patches = account_updates.into_iter().collect::<Vec<_>>();
        let (batch, lineages) = self.prepare_block_update_batch(&account_patches)?;
        let mutations = self.forest.compute_forest_mutations(block_num.as_u64(), batch)?;
        let account_states = self.precomputed_account_states_from_mutations(
            &account_patches,
            &lineages,
            &mutations,
        )?;

        Ok(PreparedAccountStateForestBlockUpdate {
            account_states,
            mutations,
            account_patches,
        })
    }

    /// Applies a snapshot-bound forest mutation set and updates the raw-key caches.
    ///
    /// Cache entries are added only after the forest mutation succeeds. This helper does not prune
    /// forest history; callers that apply canonical blocks are responsible for pruning afterward.
    ///
    /// # Errors
    ///
    /// Returns an error if the forest rejects or cannot persist the prepared mutation set.
    fn apply_precomputed_update(
        &mut self,
        block_num: BlockNumber,
        update: PreparedAccountStateForestBlockUpdate<B>,
    ) -> Result<(), LargeSmtForestError> {
        let PreparedAccountStateForestBlockUpdate {
            account_states: _,
            mutations,
            account_patches,
        } = update;

        self.forest.apply_mutations(mutations)?;

        for patch in &account_patches {
            self.cache_hashed_keys_from_patch(patch);

            trace!(
                target: crate::LOG_TARGET,
                "Updated forest with account patch",
                account.id = patch.id(),
                block.number = block_num,
                account.updated = patch.is_full_state()
            );
        }

        Ok(())
    }

    /// Applies a previously prepared block update and prunes expired forest history.
    ///
    /// `block_num` must match the value used to prepare `update`, and the forest must not have been
    /// mutated since preparation. The update is consumed and cannot be applied twice.
    ///
    /// If the block and [`PreparedAccountStateForestBlockUpdate::account_states`] have already been
    /// committed to canonical storage, an error from this method leaves the forest inconsistent
    /// with canonical state. The caller must stop normal processing and rebuild the forest before
    /// serving forest-backed state; retrying the block is not a recovery mechanism.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot apply the prepared mutations.
    pub(crate) fn apply_precomputed_block_update(
        &mut self,
        block_num: BlockNumber,
        update: PreparedAccountStateForestBlockUpdate<B>,
    ) -> Result<(), LargeSmtForestError> {
        self.apply_precomputed_update(block_num, update)?;

        let number_of_pruned_blocks = self.prune(block_num);
        miden_node_tracing::Span::current().record("num_pruned", number_of_pruned_blocks);

        Ok(())
    }

    fn apply_account_updates_without_pruning(
        &mut self,
        block_num: BlockNumber,
        account_updates: impl IntoIterator<Item = AccountPatch>,
    ) -> Result<(), AccountStateForestUpdateError> {
        let update = self.compute_block_update_mutations(block_num, account_updates)?;
        self.apply_precomputed_update(block_num, update)?;
        Ok(())
    }

    /// Rebuilds fresh account lineages from full-state account patches.
    ///
    /// Callers must ensure that every patch belongs to an account that is not already present in the
    /// forest. Rebuild pages may share a version because their account lineages are disjoint.
    ///
    /// Currently used from the loader where we're loading account states from SQLite to the account
    /// state forest.
    pub(crate) fn apply_rebuild_updates(
        &mut self,
        block_num: BlockNumber,
        account_updates: impl IntoIterator<Item = AccountPatch>,
    ) -> Result<(), AccountStateForestUpdateError> {
        self.apply_account_updates_without_pruning(block_num, account_updates)
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

#[cfg(test)]
pub(crate) trait TestAccountStateForestExt {
    fn update_account(&mut self, block_num: BlockNumber, patch: &AccountPatch);
}

#[cfg(test)]
impl<B: Backend> TestAccountStateForestExt for AccountStateForest<B> {
    fn update_account(&mut self, block_num: BlockNumber, patch: &AccountPatch) {
        self.apply_account_updates_without_pruning(block_num, [patch.clone()])
            .expect("test account forest update should succeed");
    }
}
