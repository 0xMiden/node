# Miden node store

`store` contains the persistent state-store implementation used by the Miden node. It is part of the
[Miden node](https://github.com/0xMiden/node#readme) workspace and is embedded by the `node` binary rather than operated
directly.

## Role

The store owns the node's local view of chain state. It persists blocks, notes, nullifiers, transactions, account data,
and the authenticated data structures needed to answer state queries.

## Crate-Specific Notes

The store uses RocksDB for disk-backed storage of large Sparse Merkle Trees. Building the crate requires a C/C++
toolchain and the system support needed by RocksDB bindings.

For operator-facing storage configuration, use the `node` help output and start from the
[primary README](https://github.com/0xMiden/node#readme).

## Tracing targets

Store operation spans use `miden::storage`, with more specific targets for SQLite access (`miden::storage::sqlite`), the
RocksDB-backed trees and their loader (`miden::storage::rocksdb`), and block-file storage (`miden::storage::files`).
These categories let you adjust diagnostic verbosity independently of the calling service. Tree tests using in-memory
backends retain the same target as the production tree code.

For example, `MIDEN_OTEL_FILTER=info,miden::storage::sqlite=debug` enables debug-level SQLite spans in the OpenTelemetry
export. `MIDEN_STDOUT_FILTER` controls stdout filtering; both filters fall back to `RUST_LOG` when unset. Existing
explicitly targeted log events still use `miden-store` or `user::miden-store`.

Targets are assigned at module boundaries with [`target_scope!`](../tracing/README.md#scoped-targets). Store
instrumentation uses `#[instrument_v2]` to inherit those targets, including across child modules.

## License

This project is [MIT licensed](../../LICENSE).
