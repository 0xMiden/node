# miden-large-smt-backend-rocksdb

`miden-large-smt-backend-rocksdb` provides RocksDB-backed storage for large Sparse Merkle Trees used by the Miden node
store. It is part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

The crate exposes `LargeSmt`-related types together with `RocksDbStorage` and configuration types for persisting lower
tree levels in RocksDB while keeping the upper tree levels in memory.

This backend is used by `store` when disk-backed authenticated state is enabled.

## Crate-Specific Notes

Building this crate requires the native toolchain support needed by RocksDB bindings. The exact system package names
vary by platform, so use the build error output and the node installation docs for platform-specific setup.

## License

This project is [MIT licensed](../../LICENSE).
