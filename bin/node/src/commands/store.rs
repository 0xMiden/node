use std::num::NonZeroUsize;

use miden_node_store::DatabaseOptions;
use miden_node_utils::clap::{
    AccountStateForestRocksDbOptions,
    AccountTreeRocksDbOptions,
    CliRocksDbDurabilityMode,
    NullifierTreeRocksDbOptions,
    RocksDbOptions,
    StorageOptions,
};

// STORE OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct StoreOptions {
    #[command(flatten)]
    pub sqlite: StoreSqliteOptions,

    #[command(flatten)]
    pub storage: StoreStorageOptions,
}

#[derive(clap::Args, Clone, Debug)]
pub struct StoreSqliteOptions {
    /// Maximum number of SQLite connections in the store database connection pool.
    #[arg(
        long = "store.sqlite.connection-pool-size",
        env = "MIDEN_NODE_STORE_SQLITE_CONNECTION_POOL_SIZE",
        default_value_t = miden_node_store::default_sqlite_connection_pool_size(),
        value_name = "NUM",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 40
    )]
    pub connection_pool_size: NonZeroUsize,
}

impl StoreSqliteOptions {
    pub(super) fn database_options(&self) -> DatabaseOptions {
        DatabaseOptions {
            connection_pool_size: self.connection_pool_size,
        }
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct StoreStorageOptions {
    #[command(flatten)]
    pub account_tree: AccountTreeStoreRocksDbOptions,

    #[command(flatten)]
    pub nullifier_tree: NullifierTreeStoreRocksDbOptions,

    #[command(flatten)]
    pub account_state_forest: AccountStateForestStoreRocksDbOptions,
}

impl From<StoreStorageOptions> for StorageOptions {
    fn from(value: StoreStorageOptions) -> Self {
        Self {
            account_tree: AccountTreeRocksDbOptions {
                max_open_fds: value.account_tree.max_open_fds,
                cache_size_in_bytes: value.account_tree.cache_size_in_bytes,
                durability_mode: value.account_tree.durability_mode,
            },
            nullifier_tree: NullifierTreeRocksDbOptions {
                max_open_fds: value.nullifier_tree.max_open_fds,
                cache_size_in_bytes: value.nullifier_tree.cache_size_in_bytes,
                durability_mode: value.nullifier_tree.durability_mode,
            },
            account_state_forest: AccountStateForestRocksDbOptions {
                max_open_fds: value.account_state_forest.max_open_fds,
                cache_size_in_bytes: value.account_state_forest.cache_size_in_bytes,
                durability_mode: value.account_state_forest.durability_mode,
            },
        }
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct AccountTreeStoreRocksDbOptions {
    /// Maximum number of open file descriptors for this `RocksDB` store.
    #[arg(
        id = "store.account-tree.rocksdb.max-open-fds",
        long = "store.account-tree.rocksdb.max-open-fds",
        env = "MIDEN_NODE_STORE_ACCOUNT_TREE_ROCKSDB_MAX_OPEN_FDS",
        default_value_t = default_rocksdb_max_open_fds(),
        value_name = "NUM",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 41
    )]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[arg(
        id = "store.account-tree.rocksdb.cache-size",
        long = "store.account-tree.rocksdb.cache-size",
        env = "MIDEN_NODE_STORE_ACCOUNT_TREE_ROCKSDB_CACHE_SIZE",
        default_value_t = default_rocksdb_cache_size(),
        value_name = "BYTES",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 42
    )]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[arg(
        id = "store.account-tree.rocksdb.durability-mode",
        long = "store.account-tree.rocksdb.durability-mode",
        env = "MIDEN_NODE_STORE_ACCOUNT_TREE_ROCKSDB_DURABILITY_MODE",
        value_enum,
        value_name = "MODE",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 43
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

#[derive(clap::Args, Clone, Debug)]
pub struct NullifierTreeStoreRocksDbOptions {
    /// Maximum number of open file descriptors for this `RocksDB` store.
    #[arg(
        id = "store.nullifier-tree.rocksdb.max-open-fds",
        long = "store.nullifier-tree.rocksdb.max-open-fds",
        env = "MIDEN_NODE_STORE_NULLIFIER_TREE_ROCKSDB_MAX_OPEN_FDS",
        default_value_t = default_rocksdb_max_open_fds(),
        value_name = "NUM",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 44
    )]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[arg(
        id = "store.nullifier-tree.rocksdb.cache-size",
        long = "store.nullifier-tree.rocksdb.cache-size",
        env = "MIDEN_NODE_STORE_NULLIFIER_TREE_ROCKSDB_CACHE_SIZE",
        default_value_t = default_rocksdb_cache_size(),
        value_name = "BYTES",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 45
    )]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[arg(
        id = "store.nullifier-tree.rocksdb.durability-mode",
        long = "store.nullifier-tree.rocksdb.durability-mode",
        env = "MIDEN_NODE_STORE_NULLIFIER_TREE_ROCKSDB_DURABILITY_MODE",
        value_enum,
        value_name = "MODE",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 46
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

#[derive(clap::Args, Clone, Debug)]
pub struct AccountStateForestStoreRocksDbOptions {
    /// Maximum number of open file descriptors for this `RocksDB` store.
    #[arg(
        id = "store.account-state-forest.rocksdb.max-open-fds",
        long = "store.account-state-forest.rocksdb.max-open-fds",
        env = "MIDEN_NODE_STORE_ACCOUNT_STATE_FOREST_ROCKSDB_MAX_OPEN_FDS",
        default_value_t = default_rocksdb_max_open_fds(),
        value_name = "NUM",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 47
    )]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[arg(
        id = "store.account-state-forest.rocksdb.cache-size",
        long = "store.account-state-forest.rocksdb.cache-size",
        env = "MIDEN_NODE_STORE_ACCOUNT_STATE_FOREST_ROCKSDB_CACHE_SIZE",
        default_value_t = default_rocksdb_cache_size(),
        value_name = "BYTES",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 48
    )]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[arg(
        id = "store.account-state-forest.rocksdb.durability-mode",
        long = "store.account-state-forest.rocksdb.durability-mode",
        env = "MIDEN_NODE_STORE_ACCOUNT_STATE_FOREST_ROCKSDB_DURABILITY_MODE",
        value_enum,
        value_name = "MODE",
        help_heading = super::section::STORE_CONFIGURATION_HELP_HEADING,
        display_order = 49
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

fn default_rocksdb_max_open_fds() -> i32 {
    RocksDbOptions::default().max_open_fds
}

fn default_rocksdb_cache_size() -> usize {
    RocksDbOptions::default().cache_size_in_bytes
}
