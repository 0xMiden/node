# Store component

This component persists the chain state in a `sqlite` database. It also stores each block's raw data as a file.

Merkle data structures are kept in-memory and are rebuilt on startup. Other data like account, note and nullifier
information is always read from disk. We will need to revisit this in the future but for now this is performant enough.

## Migrations

We have database migration support in place but don't actively use it yet. There is only the latest schema, and we reset
chain state (aka nuke the existing database) on each release.

Note that the migration logic includes both a schema number _and_ a hash based on the sql schema. These are both checked
on node startup to ensure that any existing database matches the expected schema. If you're seeing database failures on
startup its likely that you created the database _before_ making schema changes resulting in different schema hashes.

## RocksDB tree storage

The account and nullifier trees are persisted in separate RocksDB instances under
`<data-directory>/accounttree` and `<data-directory>/nullifiertree`, managed by
`crates/large-smt-backend-rocksdb`. Column families: `leaves`, `st24`–`st56` (subtrees at each
depth), `metadata` (root/counts), `depth24` (cached depth-24 hashes for fast startup).

Compaction parallelism and background jobs are set to `rayon::current_num_threads()` automatically.
WAL sync per write is disabled for throughput; a 512 MiB WAL cap bounds recovery time. Bloom filter
bits vary by depth (8.0–12.0) and memtables are 128 MiB per CF. See `RocksDbStorage::open` for the
full fixed configuration.

Runtime-tuneable parameters (`--{account,nullifier}_tree.rocksdb.{max_cache_size,max_open_fds}`)
are documented in the operator usage guide (`docs/external/src/operator/usage.md`).

## Architecture

The store consists mainly of a gRPC server which answers requests from the RPC and block-producer components, as well as
new block submissions from the block-producer.
