# Miden node store

`miden-node-store` contains the persistent state-store implementation used by the Miden node. It is
part of the [Miden node](https://github.com/0xMiden/node#readme) workspace and is embedded by the
`miden-node` binary rather than operated directly.

## Role

The store owns the node's local view of chain state. It persists blocks, notes, nullifiers,
transactions, account data, and the authenticated data structures needed to answer state queries.

## Crate-Specific Notes

The default `rocksdb` feature enables disk-backed storage for large Sparse Merkle Trees. Building
with this feature requires a C/C++ toolchain and the system support needed by RocksDB bindings.

For operator-facing storage configuration, use the `miden-node` help output and start from the
[primary README](https://github.com/0xMiden/node#readme).

## License

This project is [MIT licensed](../../LICENSE).
