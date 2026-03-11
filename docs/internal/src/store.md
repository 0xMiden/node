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
`<data-directory>/accounttree` and `<data-directory>/nullifiertree` respectively. Both are
managed by `crates/large-smt-backend-rocksdb`.

### Column families

| Column family | Contents |
|---|---|
| `leaves` | SMT leaf nodes keyed by their logical `u64` index (big-endian). |
| `st24`–`st56` | Serialised `Subtree` objects at depths 24, 32, 40, 48, 56. |
| `metadata` | SMT root hash, leaf count, entry count. |
| `depth24` | Cached depth-24 inner-node hashes for fast top-level reconstruction on startup. |

### Fixed tuning applied at startup

The following settings are applied unconditionally to every opened instance and cannot be changed
via CLI flags:

| Setting | Value | Rationale |
|---|---|---|
| Compaction threads (`increase_parallelism`) | `rayon::current_num_threads()` | Match CPU core count to avoid compaction falling behind under write load. |
| Background flush/compaction jobs | `rayon::current_num_threads()` | Same as above. |
| Max WAL size | 512 MiB | Bounds recovery time on restart. |
| Memtable size per CF | 128 MiB, up to 3 in-flight | Batches writes before flushing; reduces write amplification. |
| Target SST file size | 512 MiB (multiplier ×2 per level) | Reduces the number of files and keeps bloom filters effective. |
| Compaction style | Level | Predictable read/write amplification for SMT access patterns. |
| Compression | LZ4 | Fast compression with decent ratio for node data. |
| Bloom filter bits (leaves / `st32`–`st40`) | 10.0 bits/key | Tuned for point-lookup miss rate vs. memory trade-off. |
| Bloom filter bits (`st24`) | 8.0 bits/key | Shallower subtrees are queried less frequently. |
| Bloom filter bits (`st48`–`st56`) | 12.0 bits/key | Deeper subtrees are larger; more bits reduce false-positive cost. |
| WAL sync per write | disabled (`set_sync(false)`) | Throughput optimisation; RocksDB will replay the WAL on an unclean shutdown. |

### Runtime-tuneable parameters

Two parameters per tree can be adjusted at launch via CLI flags or environment variables:

| Flag | Default | Notes |
|---|---|---|
| `--account_tree.rocksdb.max_cache_size` | 2 GiB | Shared LRU block cache across all CFs. Larger is better; size to available RAM. |
| `--account_tree.rocksdb.max_open_fds` | 64 | Raise to 512+ on machines with a high `ulimit -n`. |
| `--nullifier_tree.rocksdb.max_cache_size` | 2 GiB | Same as above for the nullifier tree. |
| `--nullifier_tree.rocksdb.max_open_fds` | 64 | Same as above for the nullifier tree. |

See the [operator usage guide](../../../external/src/operator/usage.md) for deployment examples.

## Architecture

The store consists mainly of a gRPC server which answers requests from the RPC and block-producer components, as well as
new block submissions from the block-producer.
