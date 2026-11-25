use miden_crypto::merkle::smt::RocksDbSnapshotStorage;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::smt::LargeSmt;

use crate::AccountTreeWithHistory;

/// Immutable chain state at the block selected when a read is acquired.
///
/// The blockchain includes the selected block, and the trees use read-only `RocksDB` snapshots.
/// Callers use their native operations to compose reads and construct proofs at this height.
pub struct StateSnapshot<'a> {
    pub block_num: BlockNumber,
    pub blockchain: &'a Blockchain,
    pub account_tree: &'a AccountTreeWithHistory<RocksDbSnapshotStorage>,
    pub nullifier_tree: &'a NullifierTree<LargeSmt<RocksDbSnapshotStorage>>,
}
