use std::collections::BTreeMap;

use miden_node_proto::domain::account::{AccountStorageMapDetails, StorageMapEntries};
use miden_protocol::account::delta::{AccountDelta, AccountStorageDelta, AccountVaultDelta};
use miden_protocol::account::{AccountId, NonFungibleDeltaAction, StorageSlotName};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::smt::{SMT_DEPTH, SmtForest};
use miden_protocol::crypto::merkle::{EmptySubtreeRoots, MerkleError};
use miden_protocol::{EMPTY_WORD, Word};
use thiserror::Error;

#[cfg(test)]
mod tests;

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

    /// Retrieves the most recent vault SMT root for an account.
    ///
    /// Returns the latest vault root entry regardless of block number.
    /// Used when applying incremental deltas where we always want the previous state.
    ///
    /// If no vault root is found for the account, returns an empty SMT root.
    ///
    /// # Arguments
    ///
    /// * `is_full_state` - If `true`, returns an empty SMT root (for new accounts or DB
    ///   reconstruction where delta values are absolute). If `false`, looks up the previous state
    ///   (for incremental updates where delta values are relative changes).
    fn get_latest_vault_root(&self, account_id: AccountId, is_full_state: bool) -> Word {
        if is_full_state {
            return Self::empty_smt_root();
        }
        self.vault_roots
            .range((account_id, BlockNumber::GENESIS)..=(account_id, BlockNumber::from(u32::MAX)))
            .next_back()
            .map_or_else(Self::empty_smt_root, |(_, root)| *root)
    }

    /// Retrieves the most recent storage map SMT root for an account slot.
    ///
    /// Returns the latest storage root entry regardless of block number.
    /// Used when applying incremental deltas where we always want the previous state.
    ///
    /// If no storage root is found for the slot, returns an empty SMT root.
    ///
    /// # Arguments
    ///
    /// * `is_full_state` - If `true`, returns an empty SMT root (for new accounts or DB
    ///   reconstruction where delta values are absolute). If `false`, looks up the previous state
    ///   (for incremental updates where delta values are relative changes).
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
                    ..=(account_id, slot_name.clone(), BlockNumber::from(u32::MAX)),
            )
            .next_back()
            .map_or_else(Self::empty_smt_root, |(_, root)| *root)
    }

    /// Retrieves the vault SMT root for an account at or before the given block.
    /// Retrieves the storage map SMT root for an account slot at or before the given block.
    ///
    /// Finds the most recent storage root entry for the slot, since storage state persists
    /// across blocks where no changes occur.
    pub(crate) fn get_storage_root(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Word {
        self.storage_map_roots
            .range(
                (account_id, slot_name.clone(), BlockNumber::GENESIS)
                    ..=(account_id, slot_name.clone(), block_num),
            )
            .next_back()
            .map_or_else(Self::empty_smt_root, |(_, root)| *root)
    }

    /// Opens a storage map and returns storage map details with SMT proofs for the given keys.
    ///
    /// Returns `None` if no storage root is tracked for this account/slot/block combination.
    /// Returns a `MerkleError` if the forest doesn't contain sufficient data for the proofs.
    ///
    /// If the number of requested keys exceeds [`AccountStorageMapDetails::MAX_SMT_PROOF_ENTRIES`],
    /// returns `LimitExceeded`.
    pub(crate) fn open_storage_map(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
        keys: &[Word],
    ) -> Option<Result<AccountStorageMapDetails, MerkleError>> {
        let root = self.get_storage_root(account_id, &slot_name, block_num);

        // Empty root means no storage map exists for this account/slot
        if root == Self::empty_smt_root() {
            return None;
        }

        if keys.len() > AccountStorageMapDetails::MAX_SMT_PROOF_ENTRIES {
            return Some(Ok(AccountStorageMapDetails {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            }));
        }

        // Collect SMT proofs for each key
        let proofs = Result::from_iter(keys.iter().map(|key| self.forest.open(root, *key)));

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

        if !delta.vault().is_empty() {
            self.update_account_vault(block_num, account_id, delta.vault(), is_full_state)?;
        }

        if !delta.storage().is_empty() {
            self.update_account_storage(block_num, account_id, delta.storage(), is_full_state);
        }
        Ok(())
    }

    // PRIVATE METHODS
    // --------------------------------------------------------------------------------------------

    /// Updates the forest with vault changes from a delta.
    ///
    /// Processes both fungible and non-fungible asset changes, building entries for the vault SMT
    /// and tracking the new root.
    ///
    /// # Arguments
    ///
    /// * `is_full_state` - If `true`, delta values are absolute (new account or DB reconstruction).
    ///   If `false`, delta values are relative changes applied to previous state.
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
    ) -> Result<(), InnerForestError> {
        let prev_root = self.get_latest_vault_root(account_id, is_full_state);

        let mut entries = Vec::new();

        // Process fungible assets
        for (faucet_id, amount_delta) in vault_delta.fungible().iter() {
            let key: Word =
                FungibleAsset::new(*faucet_id, 0).expect("valid faucet id").vault_key().into();

            let new_amount = if is_full_state {
                // For full-state deltas, amount is the absolute value
                (*amount_delta).try_into().expect("full-state amount should be non-negative")
            } else {
                // For partial deltas, amount is a change that must be applied to previous balance.
                //
                // TODO: SmtForest only exposes `fn open()` which computes a full Merkle
                // proof. We only need the leaf, so a direct `fn get()` method would be faster.
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
                let asset: Asset = FungibleAsset::new(*faucet_id, new_amount)
                    .expect("valid fungible asset")
                    .into();
                Word::from(asset)
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
            return Ok(());
        }

        let updated_root = self
            .forest
            .batch_insert(prev_root, entries.iter().copied())
            .expect("forest insertion should succeed");

        self.vault_roots.insert((account_id, block_num), updated_root);

        tracing::debug!(
            target: crate::COMPONENT,
            %account_id,
            %block_num,
            vault_entries = entries.len(),
            "Updated vault in forest"
        );
        Ok(())
    }

    /// Updates the forest with storage map changes from a delta.
    ///
    /// Processes storage map slot deltas, building SMTs for each modified slot
    /// and tracking the new roots and accumulated entries.
    ///
    /// # Arguments
    ///
    /// * `is_full_state` - If `true`, delta values are absolute (new account or DB reconstruction).
    ///   If `false`, delta values are relative changes applied to previous state.
    fn update_account_storage(
        &mut self,
        block_num: BlockNumber,
        account_id: AccountId,
        storage_delta: &AccountStorageDelta,
        is_full_state: bool,
    ) {
        for (slot_name, map_delta) in storage_delta.maps() {
            let prev_root = self.get_latest_storage_map_root(account_id, slot_name, is_full_state);

            let delta_entries: Vec<_> =
                map_delta.entries().iter().map(|(key, value)| ((*key).into(), *value)).collect();

            if delta_entries.is_empty() {
                continue;
            }

            let updated_root = self
                .forest
                .batch_insert(prev_root, delta_entries.iter().copied())
                .expect("forest insertion should succeed");

            self.storage_map_roots
                .insert((account_id, slot_name.clone(), block_num), updated_root);

            // Accumulate entries: start from previous block's entries or empty for full state
            let mut accumulated_entries = if is_full_state {
                BTreeMap::new()
            } else {
                self.storage_entries
                    .range(
                        (account_id, slot_name.clone(), BlockNumber::GENESIS)
                            ..(account_id, slot_name.clone(), block_num),
                    )
                    .next_back()
                    .map(|(_, entries)| entries.clone())
                    .unwrap_or_default()
            };

            // Apply delta entries (insert or remove if value is EMPTY_WORD)
            for (key, value) in &delta_entries {
                if *value == EMPTY_WORD {
                    accumulated_entries.remove(key);
                } else {
                    accumulated_entries.insert(*key, *value);
                }
            }

            self.storage_entries
                .insert((account_id, slot_name.clone(), block_num), accumulated_entries);

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

    // TODO: tie in-memory forest retention to DB pruning policy once forest queries rely on it.
}
