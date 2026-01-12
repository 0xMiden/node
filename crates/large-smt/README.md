# miden-large-smt

Large-scale Sparse Merkle Tree backed by pluggable storage (RocksDB, memory).

This crate provides `LargeSmt`, a hybrid SMT implementation that stores the top of the tree
(depths 0–23) in memory and persists the lower depths (24–64) in storage as fixed-size subtrees.
This hybrid layout scales beyond RAM while keeping common operations fast.

## Migration Status

This crate is the future home for `LargeSmt` and its storage backends. Currently it re-exports
types from `miden-protocol` (which re-exports from `miden-crypto`).

The migration will be completed in phases:
1. ✅ Create this crate as a re-export layer (current state)
2. Copy the full implementation from miden-crypto to this crate
3. Update miden-crypto to remove the rocksdb feature
4. Update dependents to use this crate directly

## Features

- **concurrent**: Enables parallel processing with rayon (enabled by default)
- **rocksdb**: (Future) Enables RocksDB storage backend

## Usage

```rust
use miden_large_smt::{LargeSmt, MemoryStorage};

// Create an empty tree with in-memory storage
let storage = MemoryStorage::new();
let smt = LargeSmt::new(storage).unwrap();
```

## Re-exported Types

This crate re-exports the following types from `miden-protocol`:

- `LargeSmt` - The large-scale SMT implementation
- `LargeSmtError` - Error type for LargeSmt operations  
- `MemoryStorage` - In-memory storage backend
- `SmtStorage` - Storage backend trait
- `Subtree` - Serializable subtree representation
- `StorageUpdates` / `StorageUpdateParts` - Batch update types
- Various SMT types: `Smt`, `SmtLeaf`, `SmtProof`, `LeafIndex`, etc.
