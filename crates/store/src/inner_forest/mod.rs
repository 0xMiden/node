use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::num::NonZeroUsize;

use lru::LruCache;
use miden_node_proto::domain::account::{AccountStorageMapDetails, StorageMapEntries};
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
use miden_protocol::crypto::merkle::smt::{SMT_DEPTH, SmtForest};
use miden_protocol::crypto::merkle::{EmptySubtreeRoots, MerkleError};
use miden_protocol::errors::{AssetError, StorageMapError};
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

/// Default size for the LRU cache of latest storage map entries.
/// Used to serve `SlotData::All` queries for the most recent block.
const DEFAULT_STORAGE_CACHE_ENTRIES_SIZE: usize = 10_000;

// ERRORS
// ================================================================================================

#[derive(Debug, Error)]
pub enum InnerForestError {
    #[error(
        "balance underflow: account {account_id}, faucet {faucet_id}, \
         previous balance {prev_balance}, delta {delta}"
    )]
    BalanceUnderflow {
        account_id: AccountId,
        faucet_id: AccountId,
        prev_balance: u64,
        delta: i64,
    },
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

/// Snapshot of storage map entries at a specific block.
struct StorageSnapshot {
    block_num: BlockNumber,
    entries: BTreeMap<Word, Word>,
}

/// Container for forest-related state that needs to be updated atomically.
pub(crate) struct InnerForest {
    /// `SmtForest` for efficient account storage reconstruction.
    /// Populated during block import with storage and vault SMTs.
    forest: SmtForest,

    /// Maps (`account_id`, `slot_name`, `block_num`) to SMT root.
    /// Populated during block import for all storage map slots.
    ///
    /// Used for `SlotData::MapKeys` queries (SMT proof generation).
    /// Works for all historical blocks within retention window.
    ///
    /// Attention: Must be a `BTreeMap`, since not every block contains a value here, so we need to
    /// be able to query the previous blocks cheaply.
    storage_map_roots: BTreeMap<(AccountId, StorageSlotName, BlockNumber), Word>,

    /// LRU cache of latest storage map entries for `SlotData::All` queries.
    /// Only stores the most recent snapshot per (account, slot).
    /// Historical queries fall back to DB.
    storage_entries_per_user_block_slot: LruCache<(AccountId, StorageSlotName), StorageSnapshot>,

    vault_refcount: HashMap<Word, u64>,
    storage_slots_refcount: HashMap<Word, u64>,

    /// Maps (`account_id`, `block_num`) to vault SMT root.
    /// Tracks asset vault versions across all blocks with structural sharing.
    ///
    /// Attention: Must be a `BTreeMap`, since not every block contains a value here, so we need to
    /// be able to query the previous blocks cheaply.
    vault_roots: BTreeMap<(AccountId, BlockNumber), Word>,

    /// Tracks vault roots by block number for pruning.
    vault_roots_by_block: BTreeMap<BlockNumber, Vec<AccountId>>,

    /// Tracks storage map roots by block number for pruning.
    storage_slots_by_block: BTreeMap<BlockNumber, Vec<(AccountId, StorageSlotName)>>,
}

impl InnerForest {
    pub(crate) fn new() -> Self {
        Self {
            forest: SmtForest::new(),
            storage_map_roots: BTreeMap::new(),
            storage_entries_per_user_block_slot: LruCache::new(
                NonZeroUsize::new(DEFAULT_STORAGE_CACHE_ENTRIES_SIZE).unwrap(),
            ),
            vault_refcount: HashMap::new(),
            storage_slots_refcount: HashMap::new(),
            vault_roots: BTreeMap::new(),
            vault_roots_by_block: BTreeMap::new(),
            storage_slots_by_block: BTreeMap::new(),
        }
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of an empty SMT.
    const fn empty_smt_root() -> Word {
        *EmptySubtreeRoots::entry(SMT_DEPTH, 0)
    }

    fn increment_refcount(map: &mut HashMap<Word, u64>, root: Word) {
        let entry = map.entry(root).or_insert(0);
        *entry += 1;
    }

    fn decrement_refcount(map: &mut HashMap<Word, u64>, root: Word) -> bool {
        let Some(count) = map.get_mut(&root) else {
            return false;
        };
        if *count == 1 {
            map.remove(&root);
            true
        } else {
            *count -= 1;
            false
        }
    }

    /// Retrieves a vault root for the specified account at or before the specified block.
    pub(crate) fn get_vault_root(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Option<Word> {
        self.vault_roots
            .range((account_id, BlockNumber::GENESIS)..=(account_id, block_num))
            .next_back()
            .map(|(_, root)| *root)
    }

    /// Retrieves the storage map root for an account slot at or before the specified block.
    pub(crate) fn get_storage_map_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<Word> {
        self.storage_map_roots
            .range(
                (account_id, slot_name.clone(), BlockNumber::GENESIS)
                    ..=(account_id, slot_name.clone(), block_num),
            )
            .next_back()
            .map(|(_, root)| *root)
    }

    /// Retrieves a storage map witness for the specified account and storage slot.
    ///
    /// Finds the most recent witness at or before the specified block number.
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
        let key = StorageMap::hash_key(raw_key);
        let root = self
            .get_storage_map_root(account_id, slot_name, block_num)
            .ok_or(WitnessError::RootNotFound)?;
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
        let root = self.get_vault_root(account_id, block_num).ok_or(WitnessError::RootNotFound)?;
        let witnessees = asset_keys
            .into_iter()
            .map(|key| {
                let proof = self.forest.open(root, key.into())?;
                let asset = AssetWitness::new(proof)?;
                Ok(asset)
            })
            .collect::<Result<Vec<_>, WitnessError>>()?;
        Ok(witnessees)
    }

    /// Opens a storage map and returns storage map details with SMT proofs for the given keys.
    ///
    /// Returns `None` if no storage root is tracked for this account/slot/block combination.
    /// Returns a `MerkleError` if the forest doesn't contain sufficient data for the proofs.
    pub(crate) fn open_storage_map(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
        raw_keys: &[Word],
    ) -> Option<Result<AccountStorageMapDetails, MerkleError>> {
        let root = self.get_storage_map_root(account_id, &slot_name, block_num)?;

        // Collect SMT proofs for each key
        let proofs = Result::from_iter(raw_keys.iter().map(|raw_key| {
            let key = StorageMap::hash_key(*raw_key);
            self.forest.open(root, key)
        }));

        Some(proofs.map(|proofs| AccountStorageMapDetails::from_proofs(slot_name, proofs)))
    }

    /// Returns all key-value entries for a specific account storage slot at the latest cached
    /// block. Historical queries fall back to DB reconstruction.
    ///
    /// Returns `None` if:
    /// - No entries exist for this account/slot
    /// - Query is for a historical block (not the most recent)
    ///
    /// Returns `LimitExceeded` if there are too many entries to return.
    pub(crate) fn storage_map_entries(
        &mut self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<AccountStorageMapDetails> {
        // Get cached snapshot
        let snapshot =
            self.storage_entries_per_user_block_slot.get(&(account_id, slot_name.clone()))?;

        // Only serve queries for the latest block
        if snapshot.block_num != block_num {
            return None; // Historical query - caller should use DB
        }

        if snapshot.entries.len() > AccountStorageMapDetails::MAX_RETURN_ENTRIES {
            return Some(AccountStorageMapDetails {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            });
        }

        let entries = Vec::from_iter(snapshot.entries.iter().map(|(k, v)| (*k, *v)));
        Some(AccountStorageMapDetails::from_forest_entries(slot_name, entries))
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

        let _ = self.prune(block_num);

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
        self.vault_roots
            .range((account_id, BlockNumber::GENESIS)..=(account_id, BlockNumber::from(u32::MAX)))
            .next_back()
            .map_or_else(Self::empty_smt_root, |(_, root)| *root)
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
        assert_eq!(prev_root, Self::empty_smt_root(), "account should not be in the forest");

        // if there are no assets in the vault, add a root of an empty SMT to the vault roots map
        // so that the map has entries for all accounts, and then return (i.e., no need to insert
        // anything into the forest)
        if delta.is_empty() {
            self.vault_roots.insert((account_id, block_num), prev_root);
            self.vault_roots_by_block.entry(block_num).or_default().push(account_id);
            Self::increment_refcount(&mut self.vault_refcount, prev_root);
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
            // TODO: assert that action is addition
            entries.push((asset.vault_key().into(), asset.into()));
        }

        assert!(!entries.is_empty(), "non-empty delta should contain entries");
        let num_entries = entries.len();

        let new_root = self
            .forest
            .batch_insert(prev_root, entries)
            .expect("forest insertion should succeed");

        self.vault_roots.insert((account_id, block_num), new_root);
        self.vault_roots_by_block.entry(block_num).or_default().push(account_id);
        Self::increment_refcount(&mut self.vault_refcount, new_root);

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
        let prev_root = self.get_latest_vault_root(account_id);

        let mut entries: Vec<(Word, Word)> = Vec::new();

        // Process fungible assets
        for (faucet_id, amount_delta) in delta.fungible().iter() {
            let key: Word =
                FungibleAsset::new(*faucet_id, 0).expect("valid faucet id").vault_key().into();

            let new_amount = {
                // amount delta is a change that must be applied to previous balance.
                //
                // TODO: SmtForest only exposes `fn open()` which computes a full Merkle proof. We
                // only need the leaf, so a direct `fn get()` method would be faster.
                let prev_amount = self
                    .forest
                    .open(prev_root, key)
                    .ok()
                    .and_then(|proof| proof.get(&key))
                    .and_then(|word| FungibleAsset::try_from(word).ok())
                    .map_or(0, |asset| asset.amount());

                let new_balance = i128::from(prev_amount) + i128::from(*amount_delta);
                u64::try_from(new_balance).map_err(|_| InnerForestError::BalanceUnderflow {
                    account_id,
                    faucet_id: *faucet_id,
                    prev_balance: prev_amount,
                    delta: *amount_delta,
                })?
            };

            let value = if new_amount == 0 {
                EMPTY_WORD
            } else {
                FungibleAsset::new(*faucet_id, new_amount).expect("valid fungible asset").into()
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

        assert!(!entries.is_empty(), "non-empty delta should contain entries");
        let num_entries = entries.len();

        let new_root = self
            .forest
            .batch_insert(prev_root, entries)
            .expect("forest insertion should succeed");

        self.vault_roots.insert((account_id, block_num), new_root);
        self.vault_roots_by_block.entry(block_num).or_default().push(account_id);
        Self::increment_refcount(&mut self.vault_refcount, new_root);

        tracing::debug!(
            target: crate::COMPONENT,
            %account_id,
            %block_num,
            vault_entries = num_entries,
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
        self.storage_map_roots
            .range(
                (account_id, slot_name.clone(), BlockNumber::GENESIS)
                    ..=(account_id, slot_name.clone(), BlockNumber::from(u32::MAX)),
            )
            .next_back()
            .map_or_else(Self::empty_smt_root, |(_, root)| *root)
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

            // build a vector of entries and filter out any empty values; such values shouldn't
            // be present in full-state deltas, but it is good to exclude them explicitly
            let map_entries: Vec<(Word, Word)> = map_delta
                .entries()
                .iter()
                .filter_map(|(&key, &value)| {
                    if value == EMPTY_WORD {
                        None
                    } else {
                        Some((Word::from(key), value))
                    }
                })
                .collect();

            // if the delta is empty, make sure we create an entry in the storage map roots map
            // and update the cache
            if map_entries.is_empty() {
                self.storage_map_roots
                    .insert((account_id, slot_name.clone(), block_num), prev_root);
                self.storage_slots_by_block
                    .entry(block_num)
                    .or_default()
                    .push((account_id, slot_name.clone()));
                Self::increment_refcount(&mut self.storage_slots_refcount, prev_root);

                // Update cache with empty map
                self.storage_entries_per_user_block_slot.put(
                    (account_id, slot_name.clone()),
                    StorageSnapshot { block_num, entries: BTreeMap::new() },
                );

                continue;
            }

            // insert the updates into the forest and update storage map roots map
            let new_root = self
                .forest
                .batch_insert(prev_root, map_entries.iter().copied())
                .expect("forest insertion should succeed");

            self.storage_map_roots
                .insert((account_id, slot_name.clone(), block_num), new_root);
            self.storage_slots_by_block
                .entry(block_num)
                .or_default()
                .push((account_id, slot_name.clone()));
            Self::increment_refcount(&mut self.storage_slots_refcount, new_root);

            assert!(!map_entries.is_empty(), "a non-empty delta should have entries");
            let num_entries = map_entries.len();

            // Update cache with the entries from this insertion
            let entries = BTreeMap::from_iter(map_entries);
            self.storage_entries_per_user_block_slot
                .put((account_id, slot_name.clone()), StorageSnapshot { block_num, entries });

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
        assert!(!delta.is_empty(), "expected the delta not to be empty");

        for (slot_name, map_delta) in delta.maps() {
            // map delta shouldn't be empty, but if it is for some reason, there is nothing to do
            if map_delta.is_empty() {
                continue;
            }

            // update the storage map tree in the forest and add an entry to the storage map roots
            let prev_root = self.get_latest_storage_map_root(account_id, slot_name);
            let delta_entries: Vec<(Word, Word)> =
                map_delta.entries().iter().map(|(key, value)| ((*key).into(), *value)).collect();

            let new_root = self
                .forest
                .batch_insert(prev_root, delta_entries.iter().copied())
                .expect("forest insertion should succeed");

            self.storage_map_roots
                .insert((account_id, slot_name.clone(), block_num), new_root);
            self.storage_slots_by_block
                .entry(block_num)
                .or_default()
                .push((account_id, slot_name.clone()));
            Self::increment_refcount(&mut self.storage_slots_refcount, new_root);

            // Update cache by merging delta with latest entries
            let key = (account_id, slot_name.clone());
            let mut latest_entries = self
                .storage_entries_per_user_block_slot
                .get(&key)
                .map(|s| s.entries.clone())
                .unwrap_or_default();

            for (k, v) in &delta_entries {
                if *v == EMPTY_WORD {
                    latest_entries.remove(k);
                } else {
                    latest_entries.insert(*k, *v);
                }
            }

            self.storage_entries_per_user_block_slot
                .put(key, StorageSnapshot { block_num, entries: latest_entries });

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
    /// Only iterates over blocks in the pruning window (before cutoff). For each affected account
    /// or slot, checks if there's a newer entry before pruning - preserving the most recent state.
    ///
    /// The `SmtForest` itself is not pruned directly as it uses structural sharing and old roots
    /// are naturally garbage-collected when they become unreachable.
    ///
    /// Note: Returns (`vault_roots_removed`, `storage_roots_removed`). Storage entries count is
    /// no longer tracked since we use an LRU cache.
    #[instrument(target = COMPONENT, skip_all, fields(block.number = %chain_tip), ret)]
    pub(crate) fn prune(&mut self, chain_tip: BlockNumber) -> (usize, usize, usize) {
        let cutoff_block =
            BlockNumber::from(chain_tip.as_u32().saturating_sub(HISTORICAL_BLOCK_RETENTION));

        let vault_roots_removed = self.prune_vault_roots(cutoff_block);
        let storage_roots_removed = self.prune_storage_roots(cutoff_block);

        // Cache is self-pruning via LRU eviction
        (vault_roots_removed, storage_roots_removed, 0)
    }

    /// Prunes vault roots beyond the cutoff block.
    ///
    /// Only iterates over blocks in the pruning window, then for each affected account checks
    /// if there's a newer entry before pruning.
    fn prune_vault_roots(&mut self, cutoff_block: BlockNumber) -> usize {
        // Get blocks to prune (only blocks before cutoff)
        let blocks_to_check: Vec<BlockNumber> = self
            .vault_roots_by_block
            .range(..cutoff_block)
            .map(|(block, _)| *block)
            .collect();

        let mut roots_to_prune = HashSet::new();
        let mut roots_removed = 0usize;

        for block in blocks_to_check {
            let Some(accounts) = self.vault_roots_by_block.remove(&block) else {
                continue;
            };

            let mut accounts_to_keep = Vec::new();

            for account_id in accounts {
                // Check if there's a newer entry for this account
                let has_newer_entry = self
                    .vault_roots
                    .range((account_id, block.child())..=(account_id, BlockNumber::from(u32::MAX)))
                    .next()
                    .is_some();

                if has_newer_entry {
                    if let Some(root) = self.vault_roots.remove(&(account_id, block)) {
                        roots_removed += 1;
                        if Self::decrement_refcount(&mut self.vault_refcount, root) {
                            roots_to_prune.insert(root);
                        }
                    }
                } else {
                    accounts_to_keep.push(account_id);
                }
            }

            if !accounts_to_keep.is_empty() {
                self.vault_roots_by_block.insert(block, accounts_to_keep);
            }
        }

        self.forest.pop_smts(roots_to_prune);
        roots_removed
    }

    /// Prunes storage map roots older than/before the cutoff block.
    ///
    /// Only iterates over blocks in the pruning window, then for each affected slot checks
    /// if there's a newer entry before pruning.
    fn prune_storage_roots(&mut self, cutoff_block: BlockNumber) -> usize {
        // Get blocks to prune (only blocks before cutoff)
        let blocks_to_check: Vec<BlockNumber> = self
            .storage_slots_by_block
            .range(..cutoff_block)
            .map(|(block, _)| *block)
            .collect();

        let mut roots_to_prune = HashSet::new();
        let mut roots_removed = 0usize;

        for block in blocks_to_check {
            let Some(slots) = self.storage_slots_by_block.remove(&block) else {
                continue;
            };

            let mut slots_to_keep = Vec::new();

            for (account_id, slot_name) in slots {
                // Check if there's a newer entry for this account/slot
                let has_newer_entry = self
                    .storage_map_roots
                    .range(
                        (account_id, slot_name.clone(), block.child())
                            ..=(account_id, slot_name.clone(), BlockNumber::from(u32::MAX)),
                    )
                    .next()
                    .is_some();

                if has_newer_entry {
                    let key = (account_id, slot_name.clone(), block);
                    if let Some(root) = self.storage_map_roots.remove(&key) {
                        roots_removed += 1;
                        if Self::decrement_refcount(&mut self.storage_slots_refcount, root) {
                            roots_to_prune.insert(root);
                        }
                    }
                } else {
                    slots_to_keep.push((account_id, slot_name));
                }
            }

            if !slots_to_keep.is_empty() {
                self.storage_slots_by_block.insert(block, slots_to_keep);
            }
        }

        self.forest.pop_smts(roots_to_prune);
        roots_removed
    }
}
