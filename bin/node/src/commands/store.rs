use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_store::Store;
use miden_node_store::genesis::GenesisBlock;
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::grpc::UrlExt;
use miden_protocol::block::ProvenBlock;
use miden_protocol::utils::Deserializable;
use url::Url;

use super::{
    ENV_DATA_DIRECTORY,
    ENV_STORE_BLOCK_PRODUCER_URL,
    ENV_STORE_NTX_BUILDER_URL,
    ENV_STORE_RPC_URL,
};
use crate::commands::{ENV_BLOCK_PROVER_URL, ENV_ENABLE_OTEL};

#[expect(clippy::large_enum_variant, reason = "single use enum")]
#[derive(clap::Subcommand)]
pub enum StoreCommand {
    /// Bootstraps the blockchain database with a pre-existing genesis block.
    ///
    /// The genesis block file should be produced by `miden-node validator bootstrap`.
    Bootstrap {
        /// Directory in which to store the database and raw block data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
        /// Path to the pre-signed genesis block file produced by the validator.
        #[arg(long, value_name = "FILE")]
        genesis_block: PathBuf,
    },

    /// Starts the store component.
    ///
    /// The store exposes three separate APIs, each on a different address and with the necessary
    /// endpoints to be accessed by the node's components.
    Start {
        /// Url at which to serve the store's RPC API.
        #[arg(long = "rpc.url", env = ENV_STORE_RPC_URL, value_name = "URL")]
        rpc_url: Url,

        /// Url at which to serve the store's network transaction builder API.
        #[arg(long = "ntx-builder.url", env = ENV_STORE_NTX_BUILDER_URL, value_name = "URL")]
        ntx_builder_url: Url,

        /// Url at which to serve the store's block producer API.
        #[arg(long = "block-producer.url", env = ENV_STORE_BLOCK_PRODUCER_URL, value_name = "URL")]
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
                storage_options,
            } => {
                Self::start(
                    rpc_url,
                    ntx_builder_url,
                    block_producer_url,
                    block_prover_url,
                    data_directory,
                    grpc_options,
                    storage_options,
                )
                .await
            },
        }
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        if let Self::Start { enable_otel, .. } = self {
            *enable_otel
        } else {
            false
        }
    }

    async fn start(
        rpc_url: Url,
        ntx_builder_url: Url,
        block_producer_url: Url,
        block_prover_url: Option<Url>,
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

        let ntx_builder_addr = ntx_builder_url
            .to_socket()
            .context("Failed to extract socket address from store ntx-builder URL")?;
        let ntx_builder_listener = tokio::net::TcpListener::bind(ntx_builder_addr)
            .await
            .context("Failed to bind to store's ntx-builder gRPC URL")?;

        let block_producer_listener = block_producer_url
            .to_socket()
            .context("Failed to extract socket address from store block-producer URL")?;
        let block_producer_listener = tokio::net::TcpListener::bind(block_producer_listener)
            .await
            .context("Failed to bind to store's block-producer gRPC URL")?;

        Store {
            rpc_listener,
            block_prover_url,
            ntx_builder_listener,
            block_producer_listener,
            data_directory,
            grpc_options,
            storage_options,
        }
        .serve()
        .await
        .context("failed while serving store component")
    }
}

/// Reads a genesis block from disk, validates it, and bootstraps the store.
pub fn bootstrap_store(data_directory: &Path, genesis_block_path: &Path) -> anyhow::Result<()> {
    // Read and deserialize the genesis block file.
    let bytes = fs_err::read(genesis_block_path).context("failed to read genesis block")?;
    let proven_block = ProvenBlock::read_from_bytes(&bytes)
        .context("failed to deserialize genesis block from file")?;
    let genesis_block =
        GenesisBlock::try_from(proven_block).context("genesis block validation failed")?;

    Store::bootstrap(&genesis_block, data_directory)
}
