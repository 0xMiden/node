# rocksdb-cxx-linkage-fix

`rocksdb-cxx-linkage-fix` is a small build helper used by the Miden node workspace. It is part of the
[Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

The crate centralizes the C++ standard library linkage configuration needed by crates that build against RocksDB. It
exists to keep that build workaround in one place while the upstream RocksDB binding behavior is handled externally.

Most users should not depend on this crate directly.

## License

This project is [MIT licensed](../../LICENSE).
