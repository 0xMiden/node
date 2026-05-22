use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{
    DEFAULT_MAX_CONCURRENT_PROOFS,
    DatabaseOptions,
    Store,
    StoreMode,
    default_sqlite_connection_pool_size,
};
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::fs::ensure_empty_directory;
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
use url::Url;

use super::ENV_ENABLE_OTEL;
use crate::commands::ENV_DATA_DIRECTORY;

const ENV_RPC_LISTEN: &str = "MIDEN_NODE_STORE_RPC_LISTEN";
const ENV_UPSTREAM_URL: &str = "MIDEN_NODE_STORE_UPSTREAM_RPC_URL";
const ENV_NTX_BUILDER_LISTEN: &str = "MIDEN_NODE_STORE_NTX_BUILDER_LISTEN";
const ENV_BLOCK_PRODUCER_LISTEN: &str = "MIDEN_NODE_STORE_BLOCK_PRODUCER_LISTEN";
const ENV_BLOCK_PROVER_URL: &str = "MIDEN_NODE_STORE_BLOCK_PROVER_URL";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_NODE_STORE_SQLITE_CONNECTION_POOL_SIZE";

#[derive(clap::Subcommand)]
pub enum StoreCommand {
    /// Bootstraps the blockchain database with a pre-existing genesis block.
    ///
    /// The genesis block file should be produced by `miden-validator bootstrap`.
    Bootstrap {
        /// Directory in which to store the database and raw block data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
        /// Path to the pre-signed genesis block file produced by the validator.
        #[arg(long, value_name = "FILE")]
        genesis_block: PathBuf,
    },

    /// Starts the store in block-producer mode.
    ///
    /// In this mode the store accepts blocks from a block producer via a dedicated gRPC endpoint
    /// and runs the proof scheduler to generate block proofs.
    Start {
        /// Socket address at which to serve the store's RPC API.
        #[arg(long = "rpc.listen", env = ENV_RPC_LISTEN, value_name = "LISTEN")]
        rpc_listen: SocketAddr,

        /// Socket address at which to serve the store's network transaction builder API.
        #[arg(long = "ntx-builder.listen", env = ENV_NTX_BUILDER_LISTEN, value_name = "LISTEN")]
        ntx_builder_listen: SocketAddr,

        /// Socket address at which to serve the store's block producer API.
        #[arg(long = "block-producer.listen", env = ENV_BLOCK_PRODUCER_LISTEN, value_name = "LISTEN")]
        block_producer_listen: SocketAddr,

        /// The remote block prover's gRPC url. If not provided, a local block prover will be used.
        #[arg(long = "block-prover.url", env = ENV_BLOCK_PROVER_URL, value_name = "URL")]
        block_prover_url: Option<Url>,

        /// Directory in which to store the database and raw block data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        /// Maximum number of concurrent block proofs to be scheduled.
        #[arg(
            long = "max-concurrent-proofs",
            default_value_t = DEFAULT_MAX_CONCURRENT_PROOFS,
            value_name = "NUM"
        )]
        max_concurrent_proofs: NonZeroUsize,

        #[command(flatten)]
        grpc_options: GrpcOptionsInternal,

        /// Maximum number of SQLite connections in the store database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = default_sqlite_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,

        #[command(flatten)]
        storage_options: StorageOptions,
    },

    /// Starts the store in replica mode.
    ///
    /// In this mode the store syncs blocks from an upstream store's `Rpc` gRPC service.
    /// Only the `Rpc` gRPC service is exposed — the `BlockProducer` and `NtxBuilder` services are
    /// not started and no proof scheduler runs.
    StartReplica {
        /// Socket address at which to serve the store's RPC API.
        #[arg(long = "rpc.listen", env = ENV_RPC_LISTEN, value_name = "LISTEN")]
        rpc_listen: SocketAddr,

        /// gRPC URL of the upstream store's `Rpc` endpoint to sync blocks from.
        #[arg(long = "upstream-store.url", env = ENV_UPSTREAM_URL, value_name = "URL")]
        upstream_store_url: Url,

        /// Directory in which to store the database and raw block data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        /// Enables the exporting of traces for OpenTelemetry.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        #[command(flatten)]
        grpc_options: GrpcOptionsInternal,

        /// Maximum number of SQLite connections in the store database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = default_sqlite_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,

        #[command(flatten)]
        storage_options: StorageOptions,
    },
}

impl StoreCommand {
    /// Executes the subcommand as described by each variant's documentation.
    pub async fn handle(self) -> anyhow::Result<()> {
        match self {
            StoreCommand::Bootstrap { data_directory, genesis_block } => {
                ensure_empty_directory(&data_directory)?;
                bootstrap_store(&data_directory, &genesis_block)
            },
            StoreCommand::Start {
                rpc_listen,
                ntx_builder_listen,
                block_producer_listen,
                block_prover_url,
                data_directory,
                enable_otel: _,
                grpc_options,
                sqlite_connection_pool_size,
                max_concurrent_proofs,
                storage_options,
            } => {
                Self::start(
                    rpc_listen,
                    ntx_builder_listen,
                    block_producer_listen,
                    block_prover_url,
                    data_directory,
                    grpc_options,
                    DatabaseOptions {
                        connection_pool_size: sqlite_connection_pool_size,
                    },
                    max_concurrent_proofs,
                    storage_options,
                )
                .await
            },
            StoreCommand::StartReplica {
                rpc_listen,
                upstream_store_url,
                data_directory,
                enable_otel: _,
                grpc_options,
                sqlite_connection_pool_size,
                storage_options,
            } => {
                Self::start_replica(
                    rpc_listen,
                    upstream_store_url,
                    data_directory,
                    grpc_options,
                    DatabaseOptions {
                        connection_pool_size: sqlite_connection_pool_size,
                    },
                    storage_options,
                )
                .await
            },
        }
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        match self {
            Self::Start { enable_otel, .. } | Self::StartReplica { enable_otel, .. } => {
                *enable_otel
            },
            Self::Bootstrap { .. } => false,
        }
    }

    #[expect(clippy::too_many_arguments)]
    async fn start(
        rpc_listen: SocketAddr,
        ntx_builder_listen: SocketAddr,
        block_producer_listen: SocketAddr,
        block_prover_url: Option<Url>,
        data_directory: PathBuf,
        grpc_options: GrpcOptionsInternal,
        database_options: DatabaseOptions,
        max_concurrent_proofs: NonZeroUsize,
        storage_options: StorageOptions,
    ) -> anyhow::Result<()> {
        let rpc_listener = tokio::net::TcpListener::bind(rpc_listen)
            .await
            .context("Failed to bind to store's RPC gRPC socket")?;

        let ntx_builder_listener = tokio::net::TcpListener::bind(ntx_builder_listen)
            .await
            .context("Failed to bind to store's ntx-builder gRPC socket")?;

        let block_producer_listener = tokio::net::TcpListener::bind(block_producer_listen)
            .await
            .context("Failed to bind to store's block-producer gRPC socket")?;

        Store {
            rpc_listener,
            mode: StoreMode::BlockProducer {
                block_producer_listener,
                ntx_builder_listener,
                block_prover_url,
                max_concurrent_proofs,
            },
            data_directory,
            database_options,
            grpc_options,
            storage_options,
        }
        .serve()
        .await
        .context("failed while serving store component")
    }

    async fn start_replica(
        rpc_listen: SocketAddr,
        upstream_store_url: Url,
        data_directory: PathBuf,
        grpc_options: GrpcOptionsInternal,
        database_options: DatabaseOptions,
        storage_options: StorageOptions,
    ) -> anyhow::Result<()> {
        let rpc_listener = tokio::net::TcpListener::bind(rpc_listen)
            .await
            .context("Failed to bind to store's RPC gRPC socket")?;

        Store {
            rpc_listener,
            mode: StoreMode::Replica { upstream_url: upstream_store_url },
            data_directory,
            database_options,
            grpc_options,
            storage_options,
        }
        .serve()
        .await
        .context("failed while serving store replica component")
    }
}

/// Reads a genesis block from disk, validates it, and bootstraps the store.
pub fn bootstrap_store(data_directory: &Path, genesis_block_path: &Path) -> anyhow::Result<()> {
    // Read and deserialize the genesis block file.
    let bytes = fs_err::read(genesis_block_path).context("failed to read genesis block")?;
    let signed_block = SignedBlock::read_from_bytes(&bytes)
        .context("failed to deserialize genesis block from file")?;
    let genesis_block =
        GenesisBlock::try_from(signed_block).context("genesis block validation failed")?;

    Store::bootstrap(genesis_block, data_directory)
}
