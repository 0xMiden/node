//! `RocksDB` storage backend specific CLI argument parsing and types.

use std::path::Path;

use miden_large_smt_backend_rocksdb::{RocksDbConfig, RocksDbDurabilityMode};

pub(crate) const DEFAULT_ROCKSDB_MAX_OPEN_FDS: i32 = 64;
pub(crate) const DEFAULT_ROCKSDB_CACHE_SIZE: usize = 2 << 30;
pub(crate) const BENCH_ROCKSDB_MAX_OPEN_FDS: i32 = 512;

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliRocksDbDurabilityMode {
    Relaxed,
    Sync,
}

impl From<CliRocksDbDurabilityMode> for RocksDbDurabilityMode {
    fn from(value: CliRocksDbDurabilityMode) -> Self {
        match value {
            CliRocksDbDurabilityMode::Relaxed => Self::Relaxed,
            CliRocksDbDurabilityMode::Sync => Self::Sync,
        }
    }
}

/// Per usage options for rocksdb configuration
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct NullifierTreeRocksDbOptions {
    #[arg(
        id = "nullifier_tree_rocksdb_max_open_fds",
        long = "nullifier_tree.rocksdb.max_open_fds",
        default_value_t = DEFAULT_ROCKSDB_MAX_OPEN_FDS,
        value_name = "NULLIFIER_TREE__ROCKSDB__MAX_OPEN_FDS"
    )]
    pub max_open_fds: i32,
    #[arg(
        id = "nullifier_tree_rocksdb_max_cache_size",
        long = "nullifier_tree.rocksdb.max_cache_size",
        default_value_t = DEFAULT_ROCKSDB_CACHE_SIZE,
        value_name = "NULLIFIER_TREE__ROCKSDB__CACHE_SIZE"
    )]
    pub cache_size_in_bytes: usize,
    #[arg(
        id = "nullifier_tree_rocksdb_durability_mode",
        long = "nullifier_tree.rocksdb.durability_mode",
        value_enum,
        value_name = "NULLIFIER_TREE__ROCKSDB__DURABILITY_MODE"
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

impl Default for NullifierTreeRocksDbOptions {
    fn default() -> Self {
        RocksDbOptions::default().into()
    }
}

/// Per usage options for rocksdb configuration
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct AccountTreeRocksDbOptions {
    #[arg(
        id = "account_tree_rocksdb_max_open_fds",
        long = "account_tree.rocksdb.max_open_fds",
        default_value_t = DEFAULT_ROCKSDB_MAX_OPEN_FDS,
        value_name = "ACCOUNT_TREE__ROCKSDB__MAX_OPEN_FDS"
    )]
    pub max_open_fds: i32,
    #[arg(
        id = "account_tree_rocksdb_max_cache_size",
        long = "account_tree.rocksdb.max_cache_size",
        default_value_t = DEFAULT_ROCKSDB_CACHE_SIZE,
        value_name = "ACCOUNT_TREE__ROCKSDB__CACHE_SIZE"
    )]
    pub cache_size_in_bytes: usize,
    #[arg(
        id = "account_tree_rocksdb_durability_mode",
        long = "account_tree.rocksdb.durability_mode",
        value_enum,
        value_name = "ACCOUNT_TREE__ROCKSDB__DURABILITY_MODE"
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

impl Default for AccountTreeRocksDbOptions {
    fn default() -> Self {
        RocksDbOptions::default().into()
    }
}

/// Per usage options for rocksdb configuration
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct AccountStateForestRocksDbOptions {
    #[arg(
        id = "account_state_forest_rocksdb_max_open_fds",
        long = "account_state_forest.rocksdb.max_open_fds",
        default_value_t = DEFAULT_ROCKSDB_MAX_OPEN_FDS,
        value_name = "ACCOUNT_STATE_FOREST__ROCKSDB__MAX_OPEN_FDS"
    )]
    pub max_open_fds: i32,
    #[arg(
        id = "account_state_forest_rocksdb_max_cache_size",
        long = "account_state_forest.rocksdb.max_cache_size",
        default_value_t = DEFAULT_ROCKSDB_CACHE_SIZE,
        value_name = "ACCOUNT_STATE_FOREST__ROCKSDB__CACHE_SIZE"
    )]
    pub cache_size_in_bytes: usize,
    #[arg(
        id = "account_state_forest_rocksdb_durability_mode",
        long = "account_state_forest.rocksdb.durability_mode",
        value_enum,
        value_name = "ACCOUNT_STATE_FOREST__ROCKSDB__DURABILITY_MODE"
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

impl Default for AccountStateForestRocksDbOptions {
    fn default() -> Self {
        RocksDbOptions::default().into()
    }
}

/// General confiration options for rocksdb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbOptions {
    pub max_open_fds: i32,
    pub cache_size_in_bytes: usize,
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

impl Default for RocksDbOptions {
    fn default() -> Self {
        Self {
            max_open_fds: DEFAULT_ROCKSDB_MAX_OPEN_FDS,
            cache_size_in_bytes: DEFAULT_ROCKSDB_CACHE_SIZE,
            durability_mode: None,
        }
    }
}

impl From<AccountTreeRocksDbOptions> for RocksDbOptions {
    fn from(value: AccountTreeRocksDbOptions) -> Self {
        let AccountTreeRocksDbOptions {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        } = value;
        Self {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        }
    }
}

impl From<NullifierTreeRocksDbOptions> for RocksDbOptions {
    fn from(value: NullifierTreeRocksDbOptions) -> Self {
        let NullifierTreeRocksDbOptions {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        } = value;
        Self {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        }
    }
}

impl From<AccountStateForestRocksDbOptions> for RocksDbOptions {
    fn from(value: AccountStateForestRocksDbOptions) -> Self {
        let AccountStateForestRocksDbOptions {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        } = value;
        Self {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        }
    }
}

impl From<RocksDbOptions> for AccountTreeRocksDbOptions {
    fn from(value: RocksDbOptions) -> Self {
        let RocksDbOptions {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        } = value;
        Self {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        }
    }
}

impl From<RocksDbOptions> for NullifierTreeRocksDbOptions {
    fn from(value: RocksDbOptions) -> Self {
        let RocksDbOptions {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        } = value;
        Self {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        }
    }
}

impl From<RocksDbOptions> for AccountStateForestRocksDbOptions {
    fn from(value: RocksDbOptions) -> Self {
        let RocksDbOptions {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        } = value;
        Self {
            max_open_fds,
            cache_size_in_bytes,
            durability_mode,
        }
    }
}

impl RocksDbOptions {
    pub fn with_path(self, path: &Path) -> RocksDbConfig {
        let mut config = RocksDbConfig::new(path)
            .with_cache_size(self.cache_size_in_bytes)
            .with_max_open_files(self.max_open_fds);

        if let Some(durability_mode) = self.durability_mode {
            config = config.with_durability_mode(durability_mode.into());
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_state_forest_options_roundtrip_general_rocksdb_options() {
        let options = AccountStateForestRocksDbOptions {
            max_open_fds: 123,
            cache_size_in_bytes: 456,
            durability_mode: Some(CliRocksDbDurabilityMode::Sync),
        };

        let general = RocksDbOptions::from(options.clone());
        assert_eq!(general.max_open_fds, options.max_open_fds);
        assert_eq!(general.cache_size_in_bytes, options.cache_size_in_bytes);
        assert_eq!(general.durability_mode, options.durability_mode);

        let roundtrip = AccountStateForestRocksDbOptions::from(general);
        assert_eq!(roundtrip, options);
    }
}
