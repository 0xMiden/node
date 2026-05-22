use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use conf::Conf;
use miden_node_block_producer::{DEFAULT_MAX_BATCHES_PER_BLOCK, DEFAULT_MAX_TXS_PER_BATCH};
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{DEFAULT_MAX_CONCURRENT_PROOFS, DataDirectory, DatabaseOptions, Db, Store};
use miden_node_utils::clap::{
    AccountStateForestRocksDbOptions, AccountTreeRocksDbOptions, CliRocksDbDurabilityMode,
    GrpcOptionsExternal, GrpcOptionsInternal, NullifierTreeRocksDbOptions, RocksDbOptions,
    StorageOptions,
};
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::logging::OpenTelemetry;
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
use url::Url;

// RUNTIME OPTIONS
// ================================================================================================

#[derive(Conf, Clone, Debug)]
#[conf(env_prefix = "MIDEN_NODE_")]
pub struct RuntimeOptions {
    /// Directory in which to store the node database and raw block data.
    #[conf(long, env)]
    pub data_directory: PathBuf,

    /// Enables the exporting of traces for OpenTelemetry.
    ///
    /// This can be further configured using environment variables as defined in the official
    /// OpenTelemetry documentation. See our operator manual for further details.
    #[conf(long = "enable-otel", env)]
    pub enable_otel: bool,

    #[conf(flatten, long_prefix = "rpc.", env_prefix = "RPC_")]
    pub rpc: RpcOptions,

    #[conf(flatten, long_prefix = "store.", env_prefix = "STORE_")]
    pub store: StoreOptions,

    #[conf(flatten)]
    pub external_services: ExternalServiceOptions,
}

impl RuntimeOptions {
    pub fn open_telemetry(&self) -> OpenTelemetry {
        if self.enable_otel {
            OpenTelemetry::Enabled
        } else {
            OpenTelemetry::Disabled
        }
    }

    fn runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            data_directory: self.data_directory.clone(),
            rpc_listen: self.rpc.listen,
            validator_url: self.external_services.validator_url.clone(),
            ntx_builder_url: self.external_services.ntx_builder_url.clone(),
            database_options: self.store.sqlite.database_options(),
            internal_grpc_options: self.rpc.grpc.internal_grpc_options(),
            external_grpc_options: self.rpc.external_grpc_options(),
            storage_options: self.store.storage.clone().into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub data_directory: PathBuf,
    pub rpc_listen: SocketAddr,
    pub validator_url: Option<Url>,
    pub ntx_builder_url: Option<Url>,
    pub database_options: DatabaseOptions,
    pub internal_grpc_options: GrpcOptionsInternal,
    pub external_grpc_options: GrpcOptionsExternal,
    pub storage_options: StorageOptions,
}

// RPC OPTIONS
// ================================================================================================

#[derive(Conf, Clone, Debug)]
pub struct RpcOptions {
    /// Socket address at which to serve the public RPC API.
    #[conf(long, env)]
    pub listen: SocketAddr,

    #[conf(flatten, long_prefix = "grpc.", env_prefix = "GRPC_")]
    pub grpc: RpcGrpcOptions,

    #[conf(flatten, long_prefix = "rate-limit.", env_prefix = "RATE_LIMIT_")]
    pub rate_limit: RpcRateLimitOptions,
}

impl RpcOptions {
    pub fn external_grpc_options(&self) -> GrpcOptionsExternal {
        GrpcOptionsExternal {
            request_timeout: self.grpc.timeout,
            max_connection_age: self.grpc.max_connection_age,
            burst_size: self.rate_limit.burst_size,
            replenish_n_per_second_per_ip: self.rate_limit.replenish_per_second,
            max_concurrent_connections: self.rate_limit.max_concurrent_connections,
        }
    }
}

#[derive(Conf, Clone, Debug)]
pub struct RpcGrpcOptions {
    /// Maximum duration a gRPC request is allocated before being dropped by the server.
    #[conf(
        long,
        env,
        default_value = "10s",
        value_parser = humantime::parse_duration
    )]
    pub timeout: Duration,

    /// Maximum duration of an RPC connection before the server drops it irrespective of activity.
    #[conf(
        long,
        env,
        default_value = "30m",
        value_parser = humantime::parse_duration
    )]
    pub max_connection_age: Duration,
}

impl RpcGrpcOptions {
    pub fn internal_grpc_options(&self) -> GrpcOptionsInternal {
        GrpcOptionsInternal { request_timeout: self.timeout }
    }
}

#[derive(Conf, Clone, Debug)]
pub struct RpcRateLimitOptions {
    /// Number of RPC connections to be served before API tokens are replenished per IP address.
    #[conf(
        long,
        env,
        default(NonZeroU32::new(128).unwrap())
    )]
    pub burst_size: NonZeroU32,

    /// Number of RPC request credits replenished per second per IP.
    #[conf(
        long,
        env,
        default(NonZeroU64::new(16).unwrap())
    )]
    pub replenish_per_second: NonZeroU64,

    /// Maximum number of concurrent RPC connections accepted by the server.
    #[conf(long, env, default(1_000))]
    pub max_concurrent_connections: u64,
}

// STORE OPTIONS
// ================================================================================================

#[derive(Conf, Clone, Debug)]
pub struct StoreOptions {
    #[conf(flatten, long_prefix = "sqlite.", env_prefix = "SQLITE_")]
    pub sqlite: StoreSqliteOptions,

    #[conf(flatten)]
    pub storage: StoreStorageOptions,
}

#[derive(Conf, Clone, Debug)]
pub struct StoreSqliteOptions {
    /// Maximum number of SQLite connections in the store database connection pool.
    #[conf(long, env, default(miden_node_store::default_sqlite_connection_pool_size()))]
    pub connection_pool_size: NonZeroUsize,
}

impl StoreSqliteOptions {
    pub fn database_options(&self) -> DatabaseOptions {
        DatabaseOptions {
            connection_pool_size: self.connection_pool_size,
        }
    }
}

#[derive(Conf, Clone, Debug)]
pub struct StoreStorageOptions {
    #[conf(
        flatten,
        long_prefix = "account-tree.rocksdb.",
        env_prefix = "ACCOUNT_TREE_ROCKSDB_"
    )]
    pub account_tree: AccountTreeStoreRocksDbOptions,

    #[conf(
        flatten,
        long_prefix = "nullifier-tree.rocksdb.",
        env_prefix = "NULLIFIER_TREE_ROCKSDB_"
    )]
    pub nullifier_tree: NullifierTreeStoreRocksDbOptions,

    #[conf(
        flatten,
        long_prefix = "account-state-forest.rocksdb.",
        env_prefix = "ACCOUNT_STATE_FOREST_ROCKSDB_"
    )]
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

#[derive(Conf, Clone, Debug)]
pub struct AccountTreeStoreRocksDbOptions {
    /// Maximum number of open file descriptors for this `RocksDB` store.
    #[conf(long, env, default(default_rocksdb_max_open_fds()))]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[conf(long = "cache-size", env = "CACHE_SIZE", default(default_rocksdb_cache_size()))]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[conf(
        long,
        env,
        value_parser = parse_rocksdb_durability_mode
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

#[derive(Conf, Clone, Debug)]
pub struct NullifierTreeStoreRocksDbOptions {
    /// Maximum number of open file descriptors for this `RocksDB` store.
    #[conf(long, env, default(default_rocksdb_max_open_fds()))]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[conf(long = "cache-size", env = "CACHE_SIZE", default(default_rocksdb_cache_size()))]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[conf(
        long,
        env,
        value_parser = parse_rocksdb_durability_mode
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

#[derive(Conf, Clone, Debug)]
pub struct AccountStateForestStoreRocksDbOptions {
    /// Maximum number of open file descriptors for this `RocksDB` store.
    #[conf(long, env, default(default_rocksdb_max_open_fds()))]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[conf(long = "cache-size", env = "CACHE_SIZE", default(default_rocksdb_cache_size()))]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[conf(
        long,
        env,
        value_parser = parse_rocksdb_durability_mode
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

fn default_rocksdb_max_open_fds() -> i32 {
    RocksDbOptions::default().max_open_fds
}

fn default_rocksdb_cache_size() -> usize {
    RocksDbOptions::default().cache_size_in_bytes
}

fn parse_rocksdb_durability_mode(value: &str) -> Result<CliRocksDbDurabilityMode, &'static str> {
    match value {
        "relaxed" => Ok(CliRocksDbDurabilityMode::Relaxed),
        "sync" => Ok(CliRocksDbDurabilityMode::Sync),
        _ => Err("expected `relaxed` or `sync`"),
    }
}

// EXTERNAL SERVICES
// ================================================================================================

#[derive(Conf, Clone, Debug)]
pub struct ExternalServiceOptions {
    /// The validator service gRPC URL, if this node should use one.
    #[conf(long = "validator.url", env = "VALIDATOR_URL")]
    pub validator_url: Option<Url>,

    /// The network transaction builder service gRPC URL, if this node should use one.
    #[conf(long = "ntx-builder.url", env = "NTX_BUILDER_URL")]
    pub ntx_builder_url: Option<Url>,
}

// BOOTSTRAP
// ================================================================================================

#[derive(Conf, Clone, Debug)]
#[conf(env_prefix = "MIDEN_NODE_")]
pub struct BootstrapCommand {
    /// Directory in which to store the node database and raw block data.
    #[conf(long, env)]
    data_directory: PathBuf,

    /// Path to the pre-signed genesis block file produced by the validator.
    #[conf(long)]
    genesis_block: PathBuf,
}

impl BootstrapCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        ensure_empty_directory(&self.data_directory)?;
        bootstrap_store(&self.data_directory, &self.genesis_block)
    }
}

/// Reads a genesis block from disk, validates it, and bootstraps the store.
pub fn bootstrap_store(data_directory: &Path, genesis_block_path: &Path) -> anyhow::Result<()> {
    let bytes = fs_err::read(genesis_block_path).context("failed to read genesis block")?;
    let signed_block = SignedBlock::read_from_bytes(&bytes)
        .context("failed to deserialize genesis block from file")?;
    let genesis_block =
        GenesisBlock::try_from(signed_block).context("genesis block validation failed")?;

    Store::bootstrap(genesis_block, data_directory)
}

// MIGRATE
// ================================================================================================

#[derive(Conf, Clone, Debug)]
#[conf(env_prefix = "MIDEN_NODE_")]
pub struct MigrateCommand {
    /// Directory containing the node database.
    #[conf(long, env)]
    data_directory: PathBuf,
}

impl MigrateCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let data_directory =
            DataDirectory::load(self.data_directory.clone()).with_context(|| {
                format!("failed to load data directory at {}", self.data_directory.display())
            })?;

        Db::load(data_directory.database_path())
            .await
            .context("failed to apply store database migrations")?;

        Ok(())
    }
}

// RUNTIME MODES
// ================================================================================================

#[derive(Conf, Clone, Debug)]
pub struct SequencerCommand {
    #[conf(flatten)]
    pub runtime: RuntimeOptions,

    #[conf(flatten)]
    pub block_producer: BlockProducerOptions,
}

impl SequencerCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config();
        self.block_producer.validate()?;
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            runtime.validator_url,
            runtime.ntx_builder_url,
            self.block_producer.batch.interval,
            self.block_producer.batch_prover.url,
            self.block_producer.block.interval,
            self.block_producer.block_prover.url,
            runtime.database_options,
            runtime.internal_grpc_options,
            runtime.external_grpc_options,
            runtime.storage_options,
            self.block_producer.block.max_concurrent_proofs,
            self.block_producer.mempool.tx_capacity,
        );

        anyhow::bail!(
            "sequencer mode runtime composition is not implemented yet; this stage only defines \
             the CLI"
        )
    }
}

#[derive(Conf, Clone, Debug)]
pub struct RpcCommand {
    #[conf(flatten)]
    pub runtime: RuntimeOptions,

    #[conf(
        flatten,
        long_prefix = "sync.block-source.",
        env_prefix = "MIDEN_NODE_SYNC_BLOCK_SOURCE_"
    )]
    pub sync: SyncOptions,
}

impl RpcCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config();
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            runtime.validator_url,
            runtime.ntx_builder_url,
            runtime.database_options,
            runtime.internal_grpc_options,
            runtime.external_grpc_options,
            runtime.storage_options,
            self.sync.url,
        );

        anyhow::bail!(
            "rpc mode block-stream sync is not implemented yet; this stage only defines the CLI"
        )
    }
}

#[derive(Conf, Clone, Debug)]
pub struct SyncOptions {
    /// URL for the block stream source used to sync this node's store.
    #[conf(long, env)]
    pub url: Url,
}

// BLOCK PRODUCTION
// ================================================================================================

#[derive(Conf, Clone, Debug)]
#[conf(env_prefix = "MIDEN_NODE_")]
pub struct BlockProducerOptions {
    #[conf(flatten, long_prefix = "batch.", env_prefix = "BATCH_")]
    pub batch: BatchOptions,

    #[conf(flatten, long_prefix = "block.", env_prefix = "BLOCK_")]
    pub block: BlockOptions,

    #[conf(flatten, long_prefix = "batch-prover.", env_prefix = "BATCH_PROVER_")]
    pub batch_prover: BatchProverOptions,

    #[conf(flatten, long_prefix = "block-prover.", env_prefix = "BLOCK_PROVER_")]
    pub block_prover: BlockProverOptions,

    #[conf(flatten, long_prefix = "mempool.", env_prefix = "MEMPOOL_")]
    pub mempool: MempoolOptions,
}

impl BlockProducerOptions {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.block.max_batches > miden_protocol::MAX_BATCHES_PER_BLOCK {
            anyhow::bail!(
                "block.max-batches cannot exceed protocol limit of {}",
                miden_protocol::MAX_BATCHES_PER_BLOCK
            );
        }

        if self.batch.max_txs > miden_protocol::MAX_ACCOUNTS_PER_BATCH {
            anyhow::bail!(
                "batch.max-txs cannot exceed protocol limit of {}",
                miden_protocol::MAX_ACCOUNTS_PER_BATCH
            );
        }

        Ok(())
    }
}

#[derive(Conf, Clone, Debug)]
pub struct BatchOptions {
    /// Interval at which to produce batches.
    #[conf(
        long,
        env,
        default_value = "1s",
        value_parser = humantime::parse_duration
    )]
    pub interval: Duration,

    /// Maximum number of transactions per batch.
    #[conf(long, env, default(DEFAULT_MAX_TXS_PER_BATCH))]
    pub max_txs: usize,
}

#[derive(Conf, Clone, Debug)]
pub struct BatchProverOptions {
    /// The remote batch prover gRPC URL. If unset, a local prover will be used.
    #[conf(long, env)]
    pub url: Option<Url>,
}

#[derive(Conf, Clone, Debug)]
pub struct BlockOptions {
    /// Interval at which to produce blocks.
    #[conf(
        long,
        env,
        default_value = "3s",
        value_parser = humantime::parse_duration
    )]
    pub interval: Duration,

    /// Maximum number of batches per block.
    #[conf(long, env, default(DEFAULT_MAX_BATCHES_PER_BLOCK))]
    pub max_batches: usize,

    /// Maximum number of concurrent block proofs to be scheduled.
    #[conf(long, env, default(DEFAULT_MAX_CONCURRENT_PROOFS))]
    pub max_concurrent_proofs: NonZeroUsize,
}

#[derive(Conf, Clone, Debug)]
pub struct BlockProverOptions {
    /// The remote block prover gRPC URL. If not provided, a local block prover will be used.
    #[conf(long, env)]
    pub url: Option<Url>,
}

#[derive(Conf, Clone, Debug)]
pub struct MempoolOptions {
    /// Maximum number of uncommitted transactions allowed in the mempool.
    #[conf(long, env, default(miden_node_block_producer::DEFAULT_MEMPOOL_TX_CAPACITY))]
    pub tx_capacity: NonZeroUsize,
}
