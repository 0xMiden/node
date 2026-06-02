use std::sync::Arc;

use miden_node_utils::block_cache::BlockOrderedCache;
use miden_protocol::block::BlockNumber;

// BLOCK NOTIFICATION
// ================================================================================================

/// A committed block notification stored in the [`BlockCache`].
#[derive(Clone, Debug)]
pub struct BlockNotification(Arc<Block>);

impl BlockNotification {
    pub fn new(block_num: BlockNumber, block_bytes: Vec<u8>) -> Self {
        Self(Arc::new(Block {
            block_num,
            block_bytes,
        }))
    }

    pub fn block_num(&self) -> BlockNumber {
        self.0.block_num
    }

    pub fn block_bytes(&self) -> &[u8] {
        &self.0.block_bytes
    }
}

#[derive(Clone, Debug)]
struct Block {
    pub block_num: BlockNumber,
    pub block_bytes: Vec<u8>,
}

// PROOF NOTIFICATION
// ================================================================================================

/// A proven block notification stored in the [`ProofCache`].
#[derive(Clone, Debug)]
pub struct ProofNotification(Arc<Proof>);

impl ProofNotification {
    pub fn new(block_num: BlockNumber, proof_bytes: Vec<u8>) -> Self {
        Self(Arc::new(Proof {
            block_num,
            proof_bytes,
        }))
    }

    pub fn block_num(&self) -> BlockNumber {
        self.0.block_num
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.0.proof_bytes
    }
}

#[derive(Clone, Debug)]
struct Proof {
    block_num: BlockNumber,
    proof_bytes: Vec<u8>,
}

// CACHES
// ================================================================================================

/// FIFO cache of recent committed blocks for replica subscriptions.
pub type BlockCache = BlockOrderedCache<BlockNotification>;

/// FIFO cache of recent block proofs for replica subscriptions.
pub type ProofCache = BlockOrderedCache<ProofNotification>;
