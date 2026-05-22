use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use miden_node_block_producer::{
    DEFAULT_BATCH_INTERVAL, DEFAULT_BLOCK_INTERVAL, DEFAULT_MAX_BATCHES_PER_BLOCK,
    DEFAULT_MAX_TXS_PER_BATCH,
};
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{DEFAULT_MAX_CONCURRENT_PROOFS, DataDirectory, DatabaseOptions, Db, Store};
use miden_node_utils::clap::{
    AccountStateForestRocksDbOptions, AccountTreeRocksDbOptions, CliRocksDbDurabilityMode,
    GrpcOptionsExternal, GrpcOptionsInternal, NullifierTreeRocksDbOptions, RocksDbOptions,
    StorageOptions, duration_to_human_readable_string,
};
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::logging::OpenTelemetry;
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
use url::Url;

const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";

// RUNTIME OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RuntimeOptions {
    /// Directory in which to store the node database and raw block data.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    pub data_directory: PathBuf,

    /// Enables the exporting of traces for OpenTelemetry.
    ///
    /// This can be further configured using environment variables as defined in the official
    /// OpenTelemetry documentation. See our operator manual for further details.
    #[arg(
        long = "enable-otel",
        default_value_t = false,
        env = "MIDEN_NODE_ENABLE_OTEL",
        value_name = "BOOL"
    )]
    pub enable_otel: bool,

    #[command(flatten)]
    pub rpc: RpcOptions,

    #[command(flatten)]
    pub store: StoreOptions,

    #[command(flatten)]
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

#[derive(clap::Args, Clone, Debug)]
pub struct RpcOptions {
    /// Socket address at which to serve the public RPC API.
    #[arg(long = "rpc.listen", env = "MIDEN_NODE_RPC_LISTEN", value_name = "LISTEN")]
    pub listen: SocketAddr,

    #[command(flatten)]
    pub grpc: RpcGrpcOptions,

    #[command(flatten)]
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

#[derive(clap::Args, Clone, Debug)]
pub struct RpcGrpcOptions {
    /// Maximum duration a gRPC request is allocated before being dropped by the server.
    #[arg(
        long = "rpc.grpc.timeout",
        env = "MIDEN_NODE_RPC_GRPC_TIMEOUT",
        default_value = duration_to_human_readable_string(Duration::from_secs(10)),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub timeout: Duration,

    /// Maximum duration of an RPC connection before the server drops it irrespective of activity.
    #[arg(
        long = "rpc.grpc.max-connection-age",
        env = "MIDEN_NODE_RPC_GRPC_MAX_CONNECTION_AGE",
        default_value = duration_to_human_readable_string(Duration::from_secs(30 * 60)),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub max_connection_age: Duration,
}

impl RpcGrpcOptions {
    pub fn internal_grpc_options(&self) -> GrpcOptionsInternal {
        GrpcOptionsInternal { request_timeout: self.timeout }
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct RpcRateLimitOptions {
    /// Number of RPC connections to be served before API tokens are replenished per IP address.
    #[arg(
        long = "rpc.rate-limit.burst-size",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_BURST_SIZE",
        default_value_t = NonZeroU32::new(128).unwrap(),
        value_name = "NUM"
    )]
    pub burst_size: NonZeroU32,

    /// Number of RPC request credits replenished per second per IP.
    #[arg(
        long = "rpc.rate-limit.replenish-per-second",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_REPLENISH_PER_SECOND",
        default_value_t = NonZeroU64::new(16).unwrap(),
        value_name = "NUM"
    )]
    pub replenish_per_second: NonZeroU64,

    /// Maximum number of concurrent RPC connections accepted by the server.
    #[arg(
        long = "rpc.rate-limit.max-concurrent-connections",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_MAX_CONCURRENT_CONNECTIONS",
        default_value_t = 1_000,
        value_name = "NUM"
    )]
    pub max_concurrent_connections: u64,
}

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
        value_name = "NUM"
    )]
    pub connection_pool_size: NonZeroUsize,
}

impl StoreSqliteOptions {
    pub fn database_options(&self) -> DatabaseOptions {
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
        value_name = "NUM"
    )]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[arg(
        id = "store.account-tree.rocksdb.cache-size",
        long = "store.account-tree.rocksdb.cache-size",
        env = "MIDEN_NODE_STORE_ACCOUNT_TREE_ROCKSDB_CACHE_SIZE",
        default_value_t = default_rocksdb_cache_size(),
        value_name = "BYTES"
    )]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[arg(
        id = "store.account-tree.rocksdb.durability-mode",
        long = "store.account-tree.rocksdb.durability-mode",
        env = "MIDEN_NODE_STORE_ACCOUNT_TREE_ROCKSDB_DURABILITY_MODE",
        value_enum,
        value_name = "MODE"
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
        value_name = "NUM"
    )]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[arg(
        id = "store.nullifier-tree.rocksdb.cache-size",
        long = "store.nullifier-tree.rocksdb.cache-size",
        env = "MIDEN_NODE_STORE_NULLIFIER_TREE_ROCKSDB_CACHE_SIZE",
        default_value_t = default_rocksdb_cache_size(),
        value_name = "BYTES"
    )]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[arg(
        id = "store.nullifier-tree.rocksdb.durability-mode",
        long = "store.nullifier-tree.rocksdb.durability-mode",
        env = "MIDEN_NODE_STORE_NULLIFIER_TREE_ROCKSDB_DURABILITY_MODE",
        value_enum,
        value_name = "MODE"
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
        value_name = "NUM"
    )]
    pub max_open_fds: i32,

    /// Maximum block cache size in bytes for this `RocksDB` store.
    #[arg(
        id = "store.account-state-forest.rocksdb.cache-size",
        long = "store.account-state-forest.rocksdb.cache-size",
        env = "MIDEN_NODE_STORE_ACCOUNT_STATE_FOREST_ROCKSDB_CACHE_SIZE",
        default_value_t = default_rocksdb_cache_size(),
        value_name = "BYTES"
    )]
    pub cache_size_in_bytes: usize,

    /// `RocksDB` durability mode for this store.
    #[arg(
        id = "store.account-state-forest.rocksdb.durability-mode",
        long = "store.account-state-forest.rocksdb.durability-mode",
        env = "MIDEN_NODE_STORE_ACCOUNT_STATE_FOREST_ROCKSDB_DURABILITY_MODE",
        value_enum,
        value_name = "MODE"
    )]
    pub durability_mode: Option<CliRocksDbDurabilityMode>,
}

fn default_rocksdb_max_open_fds() -> i32 {
    RocksDbOptions::default().max_open_fds
}

fn default_rocksdb_cache_size() -> usize {
    RocksDbOptions::default().cache_size_in_bytes
}

// EXTERNAL SERVICES
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct ExternalServiceOptions {
    /// The validator service gRPC URL, if this node should use one.
    #[arg(long = "validator.url", env = "MIDEN_NODE_VALIDATOR_URL", value_name = "URL")]
    pub validator_url: Option<Url>,

    /// The network transaction builder service gRPC URL, if this node should use one.
    #[arg(long = "ntx-builder.url", env = "MIDEN_NODE_NTX_BUILDER_URL", value_name = "URL")]
    pub ntx_builder_url: Option<Url>,
}

// BOOTSTRAP
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct BootstrapCommand {
    /// Directory in which to store the node database and raw block data.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    /// Path to the pre-signed genesis block file produced by the validator.
    #[arg(long, value_name = "FILE")]
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

#[derive(clap::Args, Clone, Debug)]
pub struct MigrateCommand {
    /// Directory containing the node database.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
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

#[derive(clap::Args, Clone, Debug)]
pub struct SequencerCommand {
    #[command(flatten)]
    pub runtime: RuntimeOptions,

    #[command(flatten)]
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
            self.block_producer.block_prover.url,
            runtime.database_options,
            runtime.internal_grpc_options,
            runtime.external_grpc_options,
            runtime.storage_options,
            self.block_producer.block.max_concurrent_proofs,
        );

        anyhow::bail!(
            "sequencer mode runtime composition is not implemented yet; this stage only defines \
             the CLI"
        )
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct RpcCommand {
    #[command(flatten)]
    pub runtime: RuntimeOptions,

    #[command(flatten)]
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
            self.sync.block_source_url,
        );

        anyhow::bail!(
            "rpc mode block-stream sync is not implemented yet; this stage only defines the CLI"
        )
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct SyncOptions {
    /// URL for the block stream source used to sync this node's store.
    #[arg(
        long = "sync.block-source.url",
        env = "MIDEN_NODE_SYNC_BLOCK_SOURCE_URL",
        value_name = "URL"
    )]
    pub block_source_url: Url,
}

// BLOCK PRODUCTION
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct BlockProducerOptions {
    #[command(flatten)]
    pub batch: BatchOptions,

    #[command(flatten)]
    pub block: BlockOptions,

    #[command(flatten)]
    pub block_prover: BlockProverOptions,

    #[command(flatten)]
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

#[derive(clap::Args, Clone, Debug)]
pub struct BatchOptions {
    /// Interval at which to produce batches.
    #[arg(
        id = "batch.interval",
        long = "batch.interval",
        env = "MIDEN_NODE_BATCH_INTERVAL",
        default_value = duration_to_human_readable_string(DEFAULT_BATCH_INTERVAL),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub interval: Duration,

    /// Maximum number of transactions per batch.
    #[arg(
        id = "batch.max-txs",
        long = "batch.max-txs",
        env = "MIDEN_NODE_BATCH_MAX_TXS",
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_TXS_PER_BATCH
    )]
    pub max_txs: usize,

    /// The remote batch prover gRPC URL. If unset, a local prover will be used.
    #[arg(
        id = "batch-prover.url",
        long = "batch-prover.url",
        env = "MIDEN_NODE_BATCH_PROVER_URL",
        value_name = "URL"
    )]
    pub prover_url: Option<Url>,
}

#[derive(clap::Args, Clone, Debug)]
pub struct BlockOptions {
    /// Interval at which to produce blocks.
    #[arg(
        id = "block.interval",
        long = "block.interval",
        env = "MIDEN_NODE_BLOCK_INTERVAL",
        default_value = duration_to_human_readable_string(DEFAULT_BLOCK_INTERVAL),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub interval: Duration,

    /// Maximum number of batches per block.
    #[arg(
        id = "block.max-batches",
        long = "block.max-batches",
        env = "MIDEN_NODE_BLOCK_MAX_BATCHES",
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_BATCHES_PER_BLOCK
    )]
    pub max_batches: usize,

    /// Maximum number of concurrent block proofs to be scheduled.
    #[arg(
        id = "block.max-concurrent-proofs",
        long = "block.max-concurrent-proofs",
        env = "MIDEN_NODE_BLOCK_MAX_CONCURRENT_PROOFS",
        default_value_t = DEFAULT_MAX_CONCURRENT_PROOFS,
        value_name = "NUM"
    )]
    pub max_concurrent_proofs: NonZeroUsize,
}

#[derive(clap::Args, Clone, Debug)]
pub struct BlockProverOptions {
    /// The remote block prover gRPC URL. If not provided, a local block prover will be used.
    #[arg(
        id = "block-prover.url",
        long = "block-prover.url",
        env = "MIDEN_NODE_BLOCK_PROVER_URL",
        value_name = "URL"
    )]
    pub url: Option<Url>,
}

#[derive(clap::Args, Clone, Debug)]
pub struct MempoolOptions {
    /// Maximum number of uncommitted transactions allowed in the mempool.
    #[arg(
        id = "mempool.tx-capacity",
        long = "mempool.tx-capacity",
        default_value_t = miden_node_block_producer::DEFAULT_MEMPOOL_TX_CAPACITY,
        env = "MIDEN_NODE_MEMPOOL_TX_CAPACITY",
        value_name = "NUM"
    )]
    pub tx_capacity: NonZeroUsize,
}
