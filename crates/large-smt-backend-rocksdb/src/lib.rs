//! Large-scale Sparse Merkle Tree backed by pluggable storage.
//!
//! `LargeSmt` stores the top of the tree (depths 0–23) in memory and persists the lower
//! depths (24–64) in storage as fixed-size subtrees. This hybrid layout scales beyond RAM
//! while keeping common operations fast.
//!
//! # Usage
//!
//! ```ignore
//! use miden_large_smt::{LargeSmt, MemoryStorage};
//!
//! // Create an empty tree with in-memory storage
//! let storage = MemoryStorage::new();
//! let smt = LargeSmt::new(storage).unwrap();
//! ```
//!
//! ```ignore
//! use miden_large_smt_backend_rocksdb::{LargeSmt, RocksDbConfig, RocksDbStorage};
//!
//! let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db")).unwrap();
//! let smt = LargeSmt::new(storage).unwrap();
//! ```

extern crate alloc;

mod rocksdb;
// Re-export from miden-protocol.
pub use miden_protocol::crypto::merkle::smt::{
    InnerNode,
    LargeSmt,
    LargeSmtError,
    LeafIndex,
    MemoryStorage,
    SMT_DEPTH,
    Smt,
    SmtLeaf,
    SmtLeafError,
    SmtProof,
    SmtStorage,
    StorageError,
    StorageUpdateParts,
    StorageUpdates,
    Subtree,
    SubtreeError,
    SubtreeUpdate,
};
// Also re-export commonly used types for convenience
pub use miden_protocol::{
    EMPTY_WORD,
    Felt,
    Word,
    crypto::{
        hash::rpo::Rpo256,
        merkle::{EmptySubtreeRoots, InnerNodeInfo, MerkleError, NodeIndex, SparseMerklePath},
    },
};
pub use rocksdb::{RocksDbConfig, RocksDbStorage};
