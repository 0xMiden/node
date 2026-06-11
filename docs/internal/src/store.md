# Store component

This component persists the chain state in a `sqlite` database. It also stores each block's raw data as a file.

Merkle data structures are kept in-memory and are rebuilt on startup. Other data like account, note and nullifier
information is always read from disk. We will need to revisit this in the future but for now this is performant enough.

## Migrations

We have database migration support in place but don't actively use it yet. There is only the latest schema, and we reset
chain state (aka nuke the existing database) on each release.

## RocksDB tree storage

The account and nullifier trees are persisted in separate RocksDB instances under
`<data-directory>/accounttree` and `<data-directory>/nullifiertree`, backed by `miden-crypto`'s
`RocksDbStorage` (`miden_crypto::merkle::smt`). Column families: `leaves`, `st24`–`st56` (subtrees at
each depth), `metadata` (root/counts), `depth24` (cached depth-24 hashes for fast startup).

Compaction parallelism and background jobs are set to `rayon::current_num_threads()` automatically.
See `RocksDbStorage::open` for the full fixed configuration. The runtime-tuneable parameters (cache
size and max open file descriptors) are documented in the
[operator usage guide](https://docs.miden.xyz/core-concepts/node/operator/usage/#rocksdb-tuning).

## Architecture

The store consists mainly of state management plus a gRPC server which answers requests from the
RPC component. In sequencer mode, the block-producer uses the store state in-process for block
inputs and block application.
