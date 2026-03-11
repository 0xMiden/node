//! Public module for share clap pieces to reduce duplication

use std::num::{NonZeroU32, NonZeroU64};
#[cfg(feature = "rocksdb")]
use std::path::Path;
use std::time::Duration;

#[cfg(feature = "rocksdb")]
use miden_large_smt_backend_rocksdb::RocksDbConfig;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNECTION_AGE: Duration = Duration::from_mins(30);
const DEFAULT_REPLENISH_N_PER_SECOND_PER_IP: NonZeroU64 = NonZeroU64::new(16).unwrap();
const DEFAULT_BURST_SIZE: NonZeroU32 = NonZeroU32::new(128).unwrap();
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: u64 = 1_000;

// Formats a Duration into a human-readable string for display in clap help text
// and yields a &'static str by _leaking_ the string deliberately.
pub fn duration_to_human_readable_string(duration: Duration) -> &'static str {
    Box::new(humantime::format_duration(duration).to_string()).leak()
}

#[derive(clap::Args, Copy, Clone, Debug, PartialEq, Eq)]
pub struct GrpcOptionsInternal {
    /// Maximum duration a gRPC request is allocated before being dropped by the server.
    ///
    /// This may occur if the server is overloaded or due to an internal bug.
    #[arg(
        long = "grpc.timeout",
        default_value = duration_to_human_readable_string(DEFAULT_REQUEST_TIMEOUT),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub request_timeout: Duration,
}

impl Default for GrpcOptionsInternal {
    fn default() -> Self {
        Self { request_timeout: DEFAULT_REQUEST_TIMEOUT }
    }
}

impl From<GrpcOptionsExternal> for GrpcOptionsInternal {
    fn from(value: GrpcOptionsExternal) -> Self {
        let GrpcOptionsExternal { request_timeout, .. } = value;
        Self { request_timeout }
    }
}

impl GrpcOptionsInternal {
    pub fn test() -> Self {
        GrpcOptionsExternal::test().into()
    }
    pub fn bench() -> Self {
        GrpcOptionsExternal::bench().into()
    }
}

#[derive(clap::Args, Copy, Clone, Debug, PartialEq, Eq)]
pub struct GrpcOptionsExternal {
    /// Maximum duration a gRPC request is allocated before being dropped by the server.
    ///
    /// This may occur if the server is overloaded or due to an internal bug.
    #[arg(
        long = "grpc.timeout",
        default_value = duration_to_human_readable_string(DEFAULT_REQUEST_TIMEOUT),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub request_timeout: Duration,

    /// Maximum duration of a connection before we drop it on the server side irrespective of
    /// activity.
    #[arg(
        long = "grpc.max_connection_age",
        default_value = duration_to_human_readable_string(DEFAULT_MAX_CONNECTION_AGE),
        value_parser = humantime::parse_duration,
        value_name = "MAX_CONNECTION_AGE"
    )]
    pub max_connection_age: Duration,

    /// Number of connections to be served before the "API tokens" need to be replenished
    /// per IP address.
    #[arg(
        long = "grpc.burst_size",
        default_value_t = DEFAULT_BURST_SIZE,
        value_name = "BURST_SIZE"
    )]
    pub burst_size: NonZeroU32,

    /// Number of request credits replenished per second per IP.
    #[arg(
        long = "grpc.replenish_n_per_second",
        default_value_t = DEFAULT_REPLENISH_N_PER_SECOND_PER_IP,
        value_name = "DEFAULT_REPLENISH_N_PER_SECOND"
    )]
    pub replenish_n_per_second_per_ip: NonZeroU64,

    /// Maximum number of concurrent connections accepted by the server.
    #[arg(
        long = "grpc.max_concurrent_connections",
        default_value_t = DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        value_name = "MAX_CONCURRENT_CONNECTIONS"
    )]
    pub max_concurrent_connections: u64,
}

impl Default for GrpcOptionsExternal {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_connection_age: DEFAULT_MAX_CONNECTION_AGE,
            burst_size: DEFAULT_BURST_SIZE,
            replenish_n_per_second_per_ip: DEFAULT_REPLENISH_N_PER_SECOND_PER_IP,
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        }
    }
}

impl GrpcOptionsExternal {
    pub fn test() -> Self {
        Self {
            request_timeout: TEST_REQUEST_TIMEOUT,
            ..Default::default()
        }
    }

    /// Return a gRPC config for benchmarking.
    pub fn bench() -> Self {
        Self {
            request_timeout: Duration::from_hours(24),
            max_connection_age: Duration::from_hours(24),
            burst_size: NonZeroU32::new(100_000).unwrap(),
            replenish_n_per_second_per_ip: NonZeroU64::new(100_000).unwrap(),
            max_concurrent_connections: u64::MAX,
        }
    }
}

/// Collection of per usage storage backend configurations.
///
/// Note: Currently only contains `rocksdb` related configuration.
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct StorageOptions {
    #[cfg(feature = "rocksdb")]
    #[clap(flatten)]
    pub account_tree: AccountTreeRocksDbOptions,
    #[cfg(feature = "rocksdb")]
    #[clap(flatten)]
    pub nullifier_tree: NullifierTreeRocksDbOptions,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            account_tree: RocksDbOptions::default().into(),
            nullifier_tree: RocksDbOptions::default().into(),
        }
    }
}

impl StorageOptions {
    /// Benchmark setup.
    ///
    /// These values were determined during development of `LargeSmt`
    pub fn bench() -> Self {
        let account_tree = AccountTreeRocksDbOptions {
            max_open_fds: 512,
            cache_size_in_bytes: 2 << 30,
        };
        let nullifier_tree = NullifierTreeRocksDbOptions {
            max_open_fds: 512,
            cache_size_in_bytes: 2 << 30,
        };
        Self { account_tree, nullifier_tree }
    }
}

/// Per usage options for rocksdb configuration
#[cfg(feature = "rocksdb")]
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct NullifierTreeRocksDbOptions {
    #[arg(
        long = "nullifier_tree.rocksdb.max_open_fds",
        default_value_t = 64,
        value_name = "NULLIFIER_TREE__ROCKSDB__MAX_OPEN_FDS"
    )]
    pub max_open_fds: i32,
    #[arg(
        long = "nullifier_tree.rocksdb.max_cache_size",
        default_value_t = 2 * 1024 * 1024 * 1024,
        value_name = "NULLIFIER_TREE__ROCKSDB__CACHE_SIZE"
    )]
    pub cache_size_in_bytes: usize,
}

/// Per usage options for rocksdb configuration
#[cfg(feature = "rocksdb")]
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct AccountTreeRocksDbOptions {
    #[arg(
        long = "account_tree.rocksdb.max_open_fds",
        default_value_t = 64,
        value_name = "ACCOUNT_TREE__ROCKSDB__MAX_OPEN_FDS"
    )]
    pub max_open_fds: i32,
    #[arg(
        long = "account_tree.rocksdb.max_cache_size",
        default_value_t = 2<<30,
        value_name = "ACCOUNT_TREE__ROCKSDB__CACHE_SIZE"
    )]
    pub cache_size_in_bytes: usize,
}

/// General confiration options for rocksdb.
#[cfg(feature = "rocksdb")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbOptions {
    pub max_open_fds: i32,
    pub cache_size_in_bytes: usize,
}

#[cfg(feature = "rocksdb")]
impl Default for RocksDbOptions {
    fn default() -> Self {
        Self {
            max_open_fds: 512,
            cache_size_in_bytes: 2 << 30,
        }
    }
}

#[cfg(feature = "rocksdb")]
impl From<AccountTreeRocksDbOptions> for RocksDbOptions {
    fn from(value: AccountTreeRocksDbOptions) -> Self {
        let AccountTreeRocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

#[cfg(feature = "rocksdb")]
impl From<NullifierTreeRocksDbOptions> for RocksDbOptions {
    fn from(value: NullifierTreeRocksDbOptions) -> Self {
        let NullifierTreeRocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

#[cfg(feature = "rocksdb")]
impl From<RocksDbOptions> for AccountTreeRocksDbOptions {
    fn from(value: RocksDbOptions) -> Self {
        let RocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

#[cfg(feature = "rocksdb")]
impl From<RocksDbOptions> for NullifierTreeRocksDbOptions {
    fn from(value: RocksDbOptions) -> Self {
        let RocksDbOptions { max_open_fds, cache_size_in_bytes } = value;
        Self { max_open_fds, cache_size_in_bytes }
    }
}

#[cfg(feature = "rocksdb")]
impl RocksDbOptions {
    pub fn with_path(self, path: &Path) -> RocksDbConfig {
        RocksDbConfig::new(path)
            .with_cache_size(self.cache_size_in_bytes)
            .with_max_open_files(self.max_open_fds)
    }
}
