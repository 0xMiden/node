use std::ops::RangeInclusive;

use miden_crypto::merkle::smt::RocksDbSnapshotStorage;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::smt::LargeSmt;

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
