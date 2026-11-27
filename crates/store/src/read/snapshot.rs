use std::ops::RangeInclusive;

use miden_crypto::merkle::smt::RocksDbSnapshotStorage;
use miden_node_proto::domain::account::{AccountStorageMapDetails, AccountVaultDetails};
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::AssetId;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::smt::LargeSmt;

use crate::account_state_forest::{AccountStateForest, AccountStateForestBackendReader};
use crate::{
    AccountTreeWithHistory,
    DatabaseError,
    RangeBeyondTip,
    ScopedBlockNum,
    ScopedBlockRange,
};

/// Immutable chain state at the block selected when a read is acquired.
///
/// The blockchain includes the selected block, and the trees use read-only `RocksDB` snapshots.
/// Callers use their native operations to compose reads and construct proofs at this height.
#[non_exhaustive]
pub struct StateSnapshot<'a> {
    pub(super) forest: &'a AccountStateForest<AccountStateForestBackendReader>,
    pub block_num: BlockNumber,
    pub blockchain: &'a Blockchain,
    pub account_tree: &'a AccountTreeWithHistory<RocksDbSnapshotStorage>,
    pub nullifier_tree: &'a NullifierTree<LargeSmt<RocksDbSnapshotStorage>>,
}

impl StateSnapshot<'_> {
    /// Validates a height for a block-bounded query.
    pub fn scope_block(&self, block: BlockNumber) -> Option<ScopedBlockNum> {
        (block <= self.block_num).then(|| ScopedBlockNum::new(block))
    }

    /// Validates both ends of a range for a block-bounded query.
    pub fn scope_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> Result<ScopedBlockRange, DatabaseError> {
        if range.is_empty() {
            return Err(DatabaseError::InvalidBlockRange {
                from: *range.start(),
                to: *range.end(),
            });
        }
        if *range.end() > self.block_num {
            return Err(RangeBeyondTip {
                chain_tip: self.block_num,
                block_to: *range.end(),
            }
            .into());
        }
        Ok(ScopedBlockRange::new(range))
    }
}

impl StateSnapshot<'_> {
    /// Opens a proof of the requested assets against the account vault at the selected block.
    pub fn vault_witness(
        &self,
        account: AccountId,
        block: ScopedBlockNum,
        assets: Vec<AssetId>,
    ) -> Result<AccountVaultDetails, DatabaseError> {
        self.forest
            .get_vault_details_for_assets(account, *block, assets)
            .map_err(|err| {
                DatabaseError::DataCorrupted(format!(
                    "failed to open vault for account {account} at block {}: {err}",
                    *block
                ))
            })
    }
}

impl StateSnapshot<'_> {
    /// Opens the requested keys against the account's storage map at the selected block.
    pub fn storage_map_witness(
        &self,
        account: AccountId,
        block: ScopedBlockNum,
        slot: &StorageSlotName,
        keys: Vec<StorageMapKey>,
    ) -> Result<AccountStorageMapDetails, DatabaseError> {
        self.forest
            .get_storage_map_details_for_keys(account, slot.clone(), *block, keys)
            .ok_or_else(|| DatabaseError::StorageRootNotFound {
                account_id: account,
                slot_name: slot.to_string(),
                block_num: *block,
            })?
            .map_err(DatabaseError::MerkleError)
    }
}
