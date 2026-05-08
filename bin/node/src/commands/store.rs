use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{DEFAULT_MAX_CONCURRENT_PROOFS, Store, StoreMode};
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::grpc::UrlExt;
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
use url::Url;

use super::ENV_ENABLE_OTEL;
use crate::commands::ENV_DATA_DIRECTORY;

const ENV_URL: &str = "MIDEN_NODE_STORE_RPC_URL";
const ENV_UPSTREAM_URL: &str = "MIDEN_NODE_STORE_UPSTREAM_RPC_URL";
const ENV_NTX_BUILDER_URL: &str = "MIDEN_NODE_STORE_NTX_BUILDER_URL";
const ENV_BLOCK_PRODUCER_URL: &str = "MIDEN_NODE_STORE_BLOCK_PRODUCER_URL";
const ENV_BLOCK_PROVER_URL: &str = "MIDEN_NODE_STORE_BLOCK_PROVER_URL";

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
        /// Url at which to serve the store's RPC API.
        #[arg(long = "rpc.url", env = ENV_URL, value_name = "URL")]
        rpc_url: Url,

        /// Url at which to serve the store's network transaction builder API.
        #[arg(long = "ntx-builder.url", env = ENV_NTX_BUILDER_URL, value_name = "URL")]
        ntx_builder_url: Url,

        /// Url at which to serve the store's block producer API.
        #[arg(long = "block-producer.url", env = ENV_BLOCK_PRODUCER_URL, value_name = "URL")]
        block_producer_url: Url,

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

        #[command(flatten)]
        storage_options: StorageOptions,
    },

    /// Starts the store in replica mode.
    ///
    /// In this mode the store syncs blocks from an upstream store's `StoreReplica` gRPC service.
    /// Only the `Rpc` and `StoreReplica` gRPC services are exposed — the `BlockProducer` and
    /// `NtxBuilder` services are not started and no proof scheduler runs.
    StartReplica {
        /// Url at which to serve the store's RPC API.
        #[arg(long = "rpc.url", env = ENV_URL, value_name = "URL")]
        url: Url,

        /// gRPC URL of the upstream store's `StoreReplica` endpoint to sync blocks from.
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
                rpc_url,
                ntx_builder_url,
                block_producer_url,
                block_prover_url,
                data_directory,
                enable_otel: _,
                grpc_options,
                max_concurrent_proofs,
                storage_options,
            } => {
                Self::start(
                    rpc_url,
                    ntx_builder_url,
                    block_producer_url,
                    block_prover_url,
                    data_directory,
                    grpc_options,
                    max_concurrent_proofs,
                    storage_options,
                )
                .await
            },
            StoreCommand::StartReplica {
                url: rpc_url,
                upstream_store_url,
                data_directory,
                enable_otel: _,
                grpc_options,
                storage_options,
            } => {
                Self::start_replica(
                    rpc_url,
                    upstream_store_url,
                    data_directory,
                    grpc_options,
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
        rpc_url: Url,
        ntx_builder_url: Url,
        block_producer_url: Url,
        block_prover_url: Option<Url>,
        data_directory: PathBuf,
        grpc_options: GrpcOptionsInternal,
        max_concurrent_proofs: NonZeroUsize,
        storage_options: StorageOptions,
    ) -> anyhow::Result<()> {
        let rpc_listener = rpc_url
            .to_socket()
            .context("Failed to extract socket address from store RPC URL")?;
        let rpc_listener = tokio::net::TcpListener::bind(rpc_listener)
            .await
            .context("Failed to bind to store's RPC gRPC URL")?;

        let ntx_builder_addr = ntx_builder_url
            .to_socket()
            .context("Failed to extract socket address from store ntx-builder URL")?;
        let ntx_builder_listener = tokio::net::TcpListener::bind(ntx_builder_addr)
            .await
            .context("Failed to bind to store's ntx-builder gRPC URL")?;

        let block_producer_addr = block_producer_url
            .to_socket()
            .context("Failed to extract socket address from store block-producer URL")?;
        let block_producer_listener = tokio::net::TcpListener::bind(block_producer_addr)
            .await
            .context("Failed to bind to store's block-producer gRPC URL")?;

        Store {
            rpc_listener,
            mode: StoreMode::BlockProducer {
                block_producer_listener,
                ntx_builder_listener,
                block_prover_url,
                max_concurrent_proofs,
            },
            data_directory,
            grpc_options,
            storage_options,
        }
        .serve()
        .await
        .context("failed while serving store component")
    }

    async fn start_replica(
        rpc_url: Url,
        upstream_store_url: Url,
        data_directory: PathBuf,
        grpc_options: GrpcOptionsInternal,
        storage_options: StorageOptions,
    ) -> anyhow::Result<()> {
        let rpc_listener = rpc_url
            .to_socket()
            .context("Failed to extract socket address from store RPC URL")?;
        let rpc_listener = tokio::net::TcpListener::bind(rpc_listener)
            .await
            .context("Failed to bind to store's RPC gRPC URL")?;

        Store {
            rpc_listener,
            mode: StoreMode::Replica { upstream_url: upstream_store_url },
            data_directory,
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
