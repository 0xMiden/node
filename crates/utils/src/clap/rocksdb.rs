//! `RocksDB` storage backend specific CLI argument parsing and types.

use std::path::Path;

use miden_large_smt_backend_rocksdb::RocksDbConfig;

pub(crate) const DEFAULT_ROCKSDB_MAX_OPEN_FDS: i32 = 64;
pub(crate) const DEFAULT_ROCKSDB_CACHE_SIZE: usize = 2 << 30;
pub(crate) const BENCH_ROCKSDB_MAX_OPEN_FDS: i32 = 512;

/// Per usage options for rocksdb configuration
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct NullifierTreeRocksDbOptions {
    #[arg(
        long = "nullifier_tree.rocksdb.max_open_fds",
        default_value_t = DEFAULT_ROCKSDB_MAX_OPEN_FDS,
        value_name = "NULLIFIER_TREE__ROCKSDB__MAX_OPEN_FDS"
    )]
    pub max_open_fds: i32,
    #[arg(
        long = "nullifier_tree.rocksdb.max_cache_size",
        default_value_t = DEFAULT_ROCKSDB_CACHE_SIZE,
        value_name = "NULLIFIER_TREE__ROCKSDB__CACHE_SIZE"
    )]
    pub cache_size_in_bytes: usize,
}

/// Per usage options for rocksdb configuration
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct AccountTreeRocksDbOptions {
    #[arg(
        long = "account_tree.rocksdb.max_open_fds",
        default_value_t = DEFAULT_ROCKSDB_MAX_OPEN_FDS,
        value_name = "ACCOUNT_TREE__ROCKSDB__MAX_OPEN_FDS"
    )]
    pub max_open_fds: i32,
    #[arg(
        long = "account_tree.rocksdb.max_cache_size",
        default_value_t = DEFAULT_ROCKSDB_CACHE_SIZE,
        value_name = "ACCOUNT_TREE__ROCKSDB__CACHE_SIZE"
    )]
    pub cache_size_in_bytes: usize,
}

/// General confiration options for rocksdb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbOptions {
    pub max_open_fds: i32,
    pub cache_size_in_bytes: usize,
}

impl Default for RocksDbOptions {
    fn default() -> Self {
        Self {
            max_open_fds: DEFAULT_ROCKSDB_MAX_OPEN_FDS,
            cache_size_in_bytes: DEFAULT_ROCKSDB_CACHE_SIZE,
        }
    }
}

impl From<AccountTreeRocksDbOptions> for RocksDbOptions {
    fn from(value: AccountTreeRocksDbOptions) -> Self {
        let AccountTreeRocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

impl From<NullifierTreeRocksDbOptions> for RocksDbOptions {
    fn from(value: NullifierTreeRocksDbOptions) -> Self {
        let NullifierTreeRocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

impl From<RocksDbOptions> for AccountTreeRocksDbOptions {
    fn from(value: RocksDbOptions) -> Self {
        let RocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

impl From<RocksDbOptions> for NullifierTreeRocksDbOptions {
    fn from(value: RocksDbOptions) -> Self {
        let RocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

impl RocksDbOptions {
    pub fn with_path(self, path: &Path) -> RocksDbConfig {
        RocksDbConfig::new(path)
            .with_cache_size(self.cache_size_in_bytes)
            .with_max_open_files(self.max_open_fds)
    }
}
