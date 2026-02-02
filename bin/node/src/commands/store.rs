use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use miden_node_store::Store;
use miden_node_store::genesis::config::{AccountFileWithName, GenesisConfig};
use miden_node_utils::grpc::UrlExt;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::utils::Deserializable;
use url::Url;

use super::{
    ENV_DATA_DIRECTORY,
    ENV_STORE_BLOCK_PRODUCER_URL,
    ENV_STORE_NTX_BUILDER_URL,
    ENV_STORE_RPC_URL,
};
use crate::commands::{
    DEFAULT_TIMEOUT,
    ENV_BLOCK_PROVER_URL,
    ENV_ENABLE_OTEL,
    ENV_GENESIS_CONFIG_FILE,
    ENV_VALIDATOR_INSECURE_SECRET_KEY,
    INSECURE_VALIDATOR_KEY_HEX,
    duration_to_human_readable_string,
};

#[allow(clippy::large_enum_variant, reason = "single use enum")]
#[derive(clap::Subcommand)]
pub enum StoreCommand {
    /// Bootstraps the blockchain database with the genesis block.
    ///
    /// The genesis block contains a single public faucet account. The private key for this
    /// account is written to the `accounts-directory` which can be used to control the account.
    ///
    /// This key is not required by the node and can be moved.
    Bootstrap {
        /// Directory in which to store the database and raw block data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
        /// Directory to write the account data to.
        #[arg(long, value_name = "DIR")]
        accounts_directory: PathBuf,
        /// Use the given configuration file to construct the genesis state from.
        #[arg(long, env = ENV_GENESIS_CONFIG_FILE, value_name = "GENESIS_CONFIG")]
        genesis_config_file: Option<PathBuf>,
        /// Insecure, hex-encoded validator secret key for development and testing purposes.
        ///
        /// If not provided, a predefined key is used.
        #[arg(
            long = "validator.insecure.secret-key",
            env = ENV_VALIDATOR_INSECURE_SECRET_KEY,
            value_name = "VALIDATOR_INSECURE_SECRET_KEY",
            default_value = INSECURE_VALIDATOR_KEY_HEX
        )]
        validator_insecure_secret_key: String,
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

        /// Maximum duration a gRPC request is allocated before being dropped by the server.
        ///
        /// This may occur if the server is overloaded or due to an internal bug.
        #[arg(
            long = "grpc.timeout",
            default_value = &duration_to_human_readable_string(DEFAULT_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        grpc_timeout: Duration,
    },
}

impl StoreCommand {
    /// Executes the subcommand as described by each variants documentation.
    pub async fn handle(self) -> anyhow::Result<()> {
        match self {
            StoreCommand::Bootstrap {
                data_directory,
                accounts_directory,
                genesis_config_file,
                validator_insecure_secret_key,
            } => Self::bootstrap(
                &data_directory,
                &accounts_directory,
                genesis_config_file.as_ref(),
                validator_insecure_secret_key,
            ),
            StoreCommand::Start {
                rpc_url,
                ntx_builder_url,
                block_producer_url,
                block_prover_url,
                data_directory,
                enable_otel: _,
                grpc_timeout,
            } => {
                Self::start(
                    rpc_url,
                    ntx_builder_url,
                    block_producer_url,
                    block_prover_url,
                    data_directory,
                    grpc_timeout,
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
        grpc_timeout: Duration,
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
            grpc_timeout,
        }
        .serve()
        .await
        .context("failed while serving store component")
    }

    fn bootstrap(
        data_directory: &Path,
        accounts_directory: &Path,
        genesis_config: Option<&PathBuf>,
        validator_insecure_secret_key: String,
    ) -> anyhow::Result<()> {
        // Decode the validator key.
        let signer = SecretKey::read_from_bytes(&hex::decode(validator_insecure_secret_key)?)?;

        // Parse genesis config (or default if not given).
        let config = genesis_config
            .map(|file_path| {
                let toml_str = fs_err::read_to_string(file_path)?;
                GenesisConfig::read_toml(toml_str.as_str()).with_context(|| {
                    format!("failed to parse genesis config from file {}", file_path.display())
                })
            })
            .transpose()?
            .unwrap_or_default();

        let (genesis_state, secrets) = config.into_state(signer)?;

        // Create directories if they do not already exist.
        for directory in &[accounts_directory, data_directory] {
            if fs_err::exists(directory)? {
                let is_empty = fs_err::read_dir(directory)?.next().is_none();
                // If the directory exists and is empty, we store the files there
                if !is_empty {
                    anyhow::bail!(format!("{} exists but it is not empty.", directory.display()));
                }
            } else {
                fs_err::create_dir(directory).with_context(|| {
                    format!(
                        "failed to create {} at {}",
                        directory
                            .file_name()
                            .unwrap_or(std::ffi::OsStr::new("directory"))
                            .display(),
                        directory.display()
                    )
                })?;
            }
        }

        // Write the accounts to disk
        for item in secrets.as_account_files(&genesis_state) {
            let AccountFileWithName { account_file, name } = item?;
            let accountpath = accounts_directory.join(name);
            // do not override existing keys
            fs_err::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&accountpath)
                .context("key file already exists")?;
            account_file.write(accountpath)?;
        }

        Store::bootstrap(genesis_state, data_directory)
    }
}
