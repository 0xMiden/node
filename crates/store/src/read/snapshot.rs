use miden_crypto::merkle::smt::RocksDbSnapshotStorage;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::MerkleError;
use miden_protocol::crypto::merkle::smt::{LargeSmt, SmtProof};

use crate::AccountTreeWithHistory;
use crate::account_state_forest::{AccountStateForest, AccountStateForestBackendReader};

/// Immutable chain state at the block selected when a read is acquired.
///
/// The blockchain includes the selected block, and the trees use read-only `RocksDB` snapshots.
/// Callers use their native operations to compose reads and construct proofs at this height.
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
    /// Returns `None` if no map is tracked for that slot at that block. Only public accounts have
    /// tracked storage maps.
    pub fn open_storage_map_key(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
        key: StorageMapKey,
    ) -> Option<Result<SmtProof, MerkleError>> {
        self.forest.open_storage_map_key(account_id, slot_name, block_num, key)
    }
}
