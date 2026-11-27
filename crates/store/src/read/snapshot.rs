use miden_crypto::merkle::smt::RocksDbSnapshotStorage;
use miden_node_proto::domain::account::{AccountStorageMapDetails, AccountVaultDetails};
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::AssetId;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::MerkleError;
use miden_protocol::crypto::merkle::smt::{LargeSmt, SmtProof};

use crate::AccountTreeWithHistory;
use crate::account_state_forest::{
    AccountStateForest,
    AccountStateForestBackendReader,
    AccountStorageMapResult,
    WitnessError,
};

/// Immutable chain state at the block selected when a read is acquired.
///
/// The blockchain includes the selected block, and the trees use read-only `RocksDB` snapshots.
/// Callers use their native operations to compose reads and construct proofs at this height.
///
/// The account state forest methods take a block number and resolve a block without its own tree
/// version to the latest earlier version. Each of them treats a block after the snapshot block as
/// having no state, because that resolution would otherwise return the current state for a future
/// block.
pub struct StateSnapshot<'a> {
    pub block_num: BlockNumber,
    pub blockchain: &'a Blockchain,
    pub account_tree: &'a AccountTreeWithHistory<RocksDbSnapshotStorage>,
    pub nullifier_tree: &'a NullifierTree<LargeSmt<RocksDbSnapshotStorage>>,
    pub(crate) forest: &'a AccountStateForest<AccountStateForestBackendReader>,
}

impl StateSnapshot<'_> {
    /// Opens `key` in the storage map at `slot_name` of `account_id` as of `block_num`.
    ///
    /// Returns `None` if `block_num` is after the snapshot block, or if no map is tracked for that
    /// slot at that block. Only public accounts have tracked storage maps.
    pub fn open_storage_map_key(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
        key: StorageMapKey,
    ) -> Option<Result<SmtProof, MerkleError>> {
        if block_num > self.block_num {
            return None;
        }
        self.forest.open_storage_map_key(account_id, slot_name, block_num, key)
    }

    /// Returns every asset in the vault of `account_id` as of `block_num`.
    ///
    /// Returns [`AccountVaultDetails::LimitExceeded`] when the vault holds more than
    /// [`AccountVaultDetails::MAX_RETURN_ENTRIES`] assets, `None` when the raw key of some asset is
    /// not in the vault key cache, and [`WitnessError::RootNotFound`] if `block_num` is after the
    /// snapshot block or no vault is tracked at that block.
    pub fn get_vault_details(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<Option<AccountVaultDetails>, WitnessError> {
        if block_num > self.block_num {
            return Err(WitnessError::RootNotFound);
        }
        self.forest.get_vault_details(account_id, block_num)
    }

    /// Opens `asset_ids` in the vault of `account_id` as of `block_num` and returns them as a
    /// partial vault.
    ///
    /// Returns [`WitnessError::RootNotFound`] if `block_num` is after the snapshot block or no
    /// vault is tracked at that block.
    pub fn get_vault_details_for_assets(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        asset_ids: Vec<AssetId>,
    ) -> Result<AccountVaultDetails, WitnessError> {
        if block_num > self.block_num {
            return Err(WitnessError::RootNotFound);
        }
        self.forest.get_vault_details_for_assets(account_id, block_num, asset_ids)
    }

    /// Opens `keys` in the storage map at `slot_name` of `account_id` as of `block_num`.
    ///
    /// Returns `None` if `block_num` is after the snapshot block, or if no map is tracked for that
    /// slot at that block.
    pub fn get_storage_map_details_for_keys(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
        keys: Vec<StorageMapKey>,
    ) -> Option<Result<AccountStorageMapDetails, MerkleError>> {
        if block_num > self.block_num {
            return None;
        }
        self.forest
            .get_storage_map_details_for_keys(account_id, slot_name, block_num, keys)
    }

    /// Returns every entry of the storage map at `slot_name` of `account_id` as of `block_num`.
    ///
    /// Returns [`AccountStorageMapResult::CannotReconstructKeysFromCache`] when the raw key of some
    /// entry is not in the storage map key cache, and [`AccountStorageMapResult::NotFound`] if
    /// `block_num` is after the snapshot block or no map is tracked for that slot at that block.
    pub fn get_storage_map_details_for_all_entries(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
    ) -> Result<AccountStorageMapResult, MerkleError> {
        if block_num > self.block_num {
            return Ok(AccountStorageMapResult::NotFound);
        }
        self.forest
            .get_storage_map_details_for_all_entries(account_id, slot_name, block_num)
    }

    /// Records the raw keys of `asset_ids` in the vault key cache.
    ///
    /// The forest stores hashed vault keys, so [`Self::get_vault_details`] can only return assets
    /// whose raw keys are cached. The cache is shared by the block writer and every snapshot, so a
    /// caller that reads a vault from the database records its keys here for later reads.
    pub fn cache_vault_keys(&self, asset_ids: impl IntoIterator<Item = AssetId>) {
        self.forest
            .vault_key_cache
            .put_many(asset_ids.into_iter().map(|asset_id| (asset_id.hash(), asset_id)));
    }

    /// Records `keys` in the storage map key cache.
    ///
    /// The forest stores hashed map keys, so [`Self::get_storage_map_details_for_all_entries`] can
    /// only return entries whose raw keys are cached. The cache is shared by the block writer and
    /// every snapshot, so a caller that reads a map from the database records its keys here for
    /// later reads.
    pub fn cache_storage_map_keys(&self, keys: impl IntoIterator<Item = StorageMapKey>) {
        self.forest.cache_storage_map_keys(keys);
    }
}
