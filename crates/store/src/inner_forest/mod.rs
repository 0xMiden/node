use std::collections::{BTreeMap, BTreeSet};

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

#[cfg(test)]
mod tests;

// TYPES
// ================================================================================================

/// Precomputed account roots from in-memory SMT updates.
///
/// Contains the vault root and storage map roots computed by applying deltas to the in-memory
/// `SmtForest`. Used to avoid reloading all entries from the database when updating accounts.
#[derive(Debug, Clone, Default)]
pub struct PrecomputedAccountRoots {
    /// New vault root after applying delta (None if vault unchanged).
    pub vault_root: Option<Word>,
    /// New storage map roots by slot name after applying delta.
    pub storage_map_roots: BTreeMap<StorageSlotName, Word>,
}

/// Collection of precomputed roots for all accounts updated in a block.
pub type BlockAccountRoots = BTreeMap<AccountId, PrecomputedAccountRoots>;

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

/// Container for forest-related state that needs to be updated atomically.
pub(crate) struct InnerForest {
    /// `SmtForest` for efficient account storage reconstruction.
    /// Populated during block import with storage and vault SMTs.
    forest: SmtForest,

    /// Maps (`account_id`, `slot_name`, `block_num`) to SMT root.
    /// Populated during block import for all storage map slots.
    storage_map_roots: BTreeMap<(AccountId, StorageSlotName, BlockNumber), Word>,

    /// Maps (`account_id`, `slot_name`, `block_num`) to all key-value entries in that storage map.
    /// Accumulated from deltas - each block's entries include all entries up to that point.
    storage_entries: BTreeMap<(AccountId, StorageSlotName, BlockNumber), BTreeMap<Word, Word>>,

    /// Maps (`account_id`, `block_num`) to vault SMT root.
    /// Tracks asset vault versions across all blocks with structural sharing.
    vault_roots: BTreeMap<(AccountId, BlockNumber), Word>,
}

impl InnerForest {
    pub(crate) fn new() -> Self {
        Self {
            forest: SmtForest::new(),
            storage_map_roots: BTreeMap::new(),
            storage_entries: BTreeMap::new(),
            vault_roots: BTreeMap::new(),
        }
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of an empty SMT.
    const fn empty_smt_root() -> Word {
        *EmptySubtreeRoots::entry(SMT_DEPTH, 0)
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

    /// Returns all key-value entries for a specific account storage slot at or before a block.
    ///
    /// Uses range query semantics: finds the most recent entries at or before `block_num`.
    /// Returns `None` if no entries exist for this account/slot up to the given block.
    /// Returns `LimitExceeded` if there are too many entries to return.
    pub(crate) fn storage_map_entries(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<AccountStorageMapDetails> {
        // Find the most recent entries at or before block_num
        let entries = self
            .storage_entries
            .range(
                (account_id, slot_name.clone(), BlockNumber::GENESIS)
                    ..=(account_id, slot_name.clone(), block_num),
            )
            .next_back()
            .map(|(_, entries)| entries)?;

        if entries.len() > AccountStorageMapDetails::MAX_RETURN_ENTRIES {
            return Some(AccountStorageMapDetails {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            });
        }
        let entries = Vec::from_iter(entries.iter().map(|(k, v)| (*k, *v)));

        Some(AccountStorageMapDetails::from_forest_entries(slot_name, entries))
    }

    // PUBLIC INTERFACE
    // --------------------------------------------------------------------------------------------

    /// Applies account updates from a block to the forest and returns precomputed roots.
    ///
    /// Iterates through account updates and applies each delta to the forest. Returns the
    /// computed vault and storage map roots for each account, to be used by DB writes.
    /// Private accounts should be filtered out before calling this method.
    ///
    /// # Arguments
    ///
    /// * `block_num` - Block number for which these updates apply
    /// * `account_updates` - Iterator of `AccountDelta` for public accounts
    ///
    /// # Returns
    ///
    /// A map from account id to precomputed roots (vault root and storage map roots).
    ///
    /// # Errors
    ///
    /// Returns an error if applying a vault delta results in a negative balance.
    pub(crate) fn apply_block_updates(
        &mut self,
        block_num: BlockNumber,
        account_updates: impl IntoIterator<Item = AccountDelta>,
    ) -> Result<BlockAccountRoots, InnerForestError> {
        let mut account_roots = BlockAccountRoots::new();

        for delta in account_updates {
            let roots = self.update_account(block_num, &delta)?;
            account_roots.insert(delta.id(), roots);

            tracing::debug!(
                target: crate::COMPONENT,
                account_id = %delta.id(),
                %block_num,
                is_full_state = delta.is_full_state(),
                "Updated forest with account delta"
            );
        }
        Ok(account_roots)
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
    /// # Returns
    ///
    /// Precomputed roots for the account (vault root and storage map roots).
    ///
    /// # Errors
    ///
    /// Returns an error if applying a vault delta results in a negative balance.
    pub(crate) fn update_account(
        &mut self,
        block_num: BlockNumber,
        delta: &AccountDelta,
    ) -> Result<PrecomputedAccountRoots, InnerForestError> {
        let account_id = delta.id();
        let is_full_state = delta.is_full_state();

        let vault_root = if is_full_state || !delta.vault().is_empty() {
            Some(self.update_account_vault(block_num, account_id, delta.vault(), is_full_state)?)
        } else {
            None
        };

        let storage_map_roots = if delta.storage().is_empty() {
            BTreeMap::new()
        } else {
            self.update_account_storage(block_num, account_id, delta.storage(), is_full_state)
        };

        Ok(PrecomputedAccountRoots { vault_root, storage_map_roots })
    }

    // ASSET VAULT DELTA PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Retrieves the most recent vault SMT root for an account.
    /// If `is_full_state` is true, returns an empty SMT root.
    fn get_latest_vault_root(&self, account_id: AccountId, is_full_state: bool) -> Word {
        if is_full_state {
            return Self::empty_smt_root();
        }

        self.vault_roots
            .range((account_id, BlockNumber::GENESIS)..=(account_id, BlockNumber::MAX))
            .next_back()
            .map_or_else(Self::empty_smt_root, |(_, root)| *root)
    }

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
        is_full_state: bool,
    ) -> Result<Word, InnerForestError> {
        let prev_root = self.get_latest_vault_root(account_id, is_full_state);

        let mut entries: Vec<(Word, Word)> = Vec::new();

        // Process fungible assets
        for (faucet_id, amount_delta) in vault_delta.fungible().iter() {
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
        for (asset, action) in vault_delta.non_fungible().iter() {
            let value = match action {
                NonFungibleDeltaAction::Add => Word::from(Asset::NonFungible(*asset)),
                NonFungibleDeltaAction::Remove => EMPTY_WORD,
            };
            entries.push((asset.vault_key().into(), value));
        }

        if entries.is_empty() {
            if is_full_state {
                self.vault_roots.insert((account_id, block_num), prev_root);
            }
            return Ok(prev_root);
        }

        let num_entries = entries.len();

        let new_root = self
            .forest
            .batch_insert(prev_root, entries)
            .expect("forest insertion should succeed");

        self.vault_roots.insert((account_id, block_num), new_root);

        tracing::debug!(
            target: crate::COMPONENT,
            %account_id,
            %block_num,
            vault_entries = num_entries,
            "Updated vault in forest"
        );
        Ok(new_root)
    }

    // STORAGE MAP DELTA PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Retrieves the most recent storage map SMT root for an account slot.
    /// If `is_full_state` is true, returns an empty SMT root.
    fn get_latest_storage_map_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        is_full_state: bool,
    ) -> Word {
        if is_full_state {
            return Self::empty_smt_root();
        }

        self.storage_map_roots
            .range(
                (account_id, slot_name.clone(), BlockNumber::GENESIS)
                    ..=(account_id, slot_name.clone(), BlockNumber::MAX),
            )
            .next_back()
            .map_or_else(Self::empty_smt_root, |(_, root)| *root)
    }

    /// Retrieves the most recent entries in the specified storage map. If no storage map exists
    /// returns an empty map.
    fn get_latest_storage_map_entries(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
    ) -> BTreeMap<Word, Word> {
        self.storage_entries
            .range(
                (account_id, slot_name.clone(), BlockNumber::GENESIS)
                    ..(account_id, slot_name.clone(), BlockNumber::MAX),
            )
            .next_back()
            .map(|(_, entries)| entries.clone())
            .unwrap_or_default()
    }

    /// Updates the forest with storage map changes from a delta and returns updated roots.
    ///
    /// Processes storage map slot deltas, building SMTs for each modified slot
    /// and tracking the new roots and accumulated entries.
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
        is_full_state: bool,
    ) -> BTreeMap<StorageSlotName, Word> {
        let mut updated_roots = BTreeMap::new();

        for (slot_name, map_delta) in storage_delta.maps() {
            let prev_root = self.get_latest_storage_map_root(account_id, slot_name, is_full_state);
            if is_full_state {
                assert_eq!(
                    prev_root,
                    Self::empty_smt_root(),
                    "account should not be in the forest"
                );
            }

            let delta_entries = if is_full_state {
                Vec::from_iter(map_delta.entries().iter().filter_map(|(&key, &value)| {
                    if value == EMPTY_WORD {
                        None
                    } else {
                        Some((Word::from(key), value))
                    }
                }))
            } else {
                Vec::from_iter(
                    map_delta.entries().iter().map(|(key, value)| ((*key).into(), *value)),
                )
            };

            if delta_entries.is_empty() {
                if is_full_state {
                    self.storage_map_roots
                        .insert((account_id, slot_name.clone(), block_num), prev_root);
                    self.storage_entries
                        .insert((account_id, slot_name.clone(), block_num), BTreeMap::new());
                    updated_roots.insert(slot_name.clone(), prev_root);
                }
                continue;
            }

            let updated_root = self
                .forest
                .batch_insert(prev_root, delta_entries.iter().copied())
                .expect("forest insertion should succeed");

            self.storage_map_roots
                .insert((account_id, slot_name.clone(), block_num), updated_root);
            updated_roots.insert(slot_name.clone(), updated_root);

            let entries = if is_full_state {
                BTreeMap::from_iter(delta_entries.iter().copied())
            } else {
                let mut latest_entries = self.get_latest_storage_map_entries(account_id, slot_name);
                for (key, value) in &delta_entries {
                    if *value == EMPTY_WORD {
                        latest_entries.remove(key);
                    } else {
                        latest_entries.insert(*key, *value);
                    }
                }
                latest_entries
            };

            self.storage_entries.insert((account_id, slot_name.clone(), block_num), entries);

            tracing::debug!(
                target: crate::COMPONENT,
                %account_id,
                %block_num,
                ?slot_name,
                delta_entries = delta_entries.len(),
                "Updated storage map in forest"
            );
        }

        updated_roots
    }

    // TODO: tie in-memory forest retention to DB pruning policy once forest queries rely on it.
}
