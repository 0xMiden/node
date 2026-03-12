use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_store::genesis::config::{AccountFileWithName, GenesisConfig};
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::grpc::UrlExt;
use miden_node_utils::signer::BlockSigner;
use miden_node_validator::{Validator, ValidatorSigner};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::utils::{Deserializable, Serializable};
use url::Url;

use crate::commands::{
    ENV_DATA_DIRECTORY,
    ENV_ENABLE_OTEL,
    ENV_GENESIS_CONFIG_FILE,
    ENV_VALIDATOR_KEY,
    ENV_VALIDATOR_KMS_KEY_ID,
    ENV_VALIDATOR_URL,
    INSECURE_VALIDATOR_KEY_HEX,
    ValidatorKey,
};

/// The filename used for the genesis block file.
pub const GENESIS_BLOCK_FILENAME: &str = "genesis.dat";

#[derive(clap::Subcommand)]
pub enum ValidatorCommand {
    /// Bootstraps the genesis block.
    ///
    /// Creates accounts from the genesis configuration, builds and signs the genesis block,
    /// and writes the signed block and account secret files to disk.
    Bootstrap {
        /// Directory in which to write the genesis block file.
        #[arg(long, value_name = "DIR")]
        genesis_block_directory: PathBuf,
        /// Directory to write the account secret files (.mac) to.
        #[arg(long, value_name = "DIR")]
        accounts_directory: PathBuf,
        /// Use the given configuration file to construct the genesis state from.
        #[arg(long, env = ENV_GENESIS_CONFIG_FILE, value_name = "GENESIS_CONFIG")]
        genesis_config_file: Option<PathBuf>,
        /// Configuration for the Validator key used to sign the genesis block.
        #[command(flatten)]
        validator_key: ValidatorKey,
    },

    /// Starts the validator component.
    Start {
        /// Url at which to serve the gRPC API.
        #[arg(env = ENV_VALIDATOR_URL)]
        url: Url,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = true, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        #[command(flatten)]
        grpc_options: GrpcOptionsInternal,

        /// Directory in which to store the validator's data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        /// Insecure, hex-encoded validator secret key for development and testing purposes.
        ///
        /// If not provided, a predefined key is used.
        ///
        /// Cannot be used with `key.kms-id`.
        #[arg(
            long = "key.hex",
            env = ENV_VALIDATOR_KEY,
            value_name = "VALIDATOR_KEY",
            default_value = INSECURE_VALIDATOR_KEY_HEX,
            group = "key"
        )]
        validator_key: String,

        /// Key ID for the KMS key used by validator to sign blocks.
        ///
        /// Cannot be used with `key.hex`.
        #[arg(
            long = "key.kms-id",
            env = ENV_VALIDATOR_KMS_KEY_ID,
            value_name = "VALIDATOR_KMS_KEY_ID",
            group = "key"
        )]
        kms_key_id: Option<String>,
    },
}

impl ValidatorCommand {
    /// Runs the validator command.
    pub async fn handle(self) -> anyhow::Result<()> {
        match self {
            Self::Bootstrap {
                genesis_block_directory,
                accounts_directory,
                genesis_config_file,
                validator_key,
            } => {
                bootstrap_genesis(
                    &genesis_block_directory,
                    &accounts_directory,
                    genesis_config_file.as_ref(),
                    validator_key,
                )
                .await
            },
            Self::Start {
                url,
                grpc_options,
                validator_key,
                data_directory,
                kms_key_id,
                ..
            } => {
                let address = url
                    .to_socket()
                    .context("failed to extract socket address from validator URL")?;

                // Run validator with KMS key backend if key id provided.
                if let Some(kms_key_id) = kms_key_id {
                    let signer = ValidatorSigner::new_kms(kms_key_id).await?;
                    Self::serve(address, grpc_options, signer, data_directory).await
                } else {
                    let signer = SecretKey::read_from_bytes(hex::decode(validator_key)?.as_ref())?;
                    let signer = ValidatorSigner::new_local(signer);
                    Self::serve(address, grpc_options, signer, data_directory).await
                }
            },
        }
    }

    /// Runs the validator component until failure.
    async fn serve(
        address: SocketAddr,
        grpc_options: GrpcOptionsInternal,
        signer: ValidatorSigner,
        data_directory: PathBuf,
    ) -> anyhow::Result<()> {
        Validator {
            address,
            grpc_options,
            signer,
            data_directory,
        }
        .serve()
        .await
        .context("failed while serving validator component")
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        match self {
            Self::Start { enable_otel, .. } => *enable_otel,
            Self::Bootstrap { .. } => false,
        }
    }
}

/// Bootstraps the genesis block: creates accounts, signs the block, and writes artifacts to disk.
///
/// This is extracted as a free function so it can be reused by the bundled bootstrap command.
pub async fn bootstrap_genesis(
    genesis_block_directory: &Path,
    accounts_directory: &Path,
    genesis_config: Option<&PathBuf>,
    validator_key: ValidatorKey,
) -> anyhow::Result<()> {
    // Parse genesis config (or default if not given).
    let config = genesis_config
        .map(|file_path| {
            GenesisConfig::read_toml_file(file_path).with_context(|| {
                format!("failed to parse genesis config from file {}", file_path.display())
            })
        })
        .transpose()?
        .unwrap_or_default();

    // Create directories if they do not already exist.
    for directory in [accounts_directory, genesis_block_directory] {
        ensure_empty_directory(directory)?;
    }

    // Bootstrap with KMS key or local key.
    let signer = validator_key.into_signer().await?;
    match signer {
        ValidatorSigner::Kms(signer) => {
            build_and_write_genesis(config, signer, accounts_directory, genesis_block_directory)
                .await
        },
        ValidatorSigner::Local(signer) => {
            build_and_write_genesis(config, signer, accounts_directory, genesis_block_directory)
                .await
        },
    }
}

/// Builds the genesis state, writes account secret files, signs the genesis block, and writes it
/// to disk.
async fn build_and_write_genesis(
    config: GenesisConfig,
    signer: impl BlockSigner,
    accounts_directory: &Path,
    genesis_block_directory: &Path,
) -> anyhow::Result<()> {
    // Build genesis state with the provided signer.
    let (genesis_state, secrets) = config.into_state(signer)?;

    // Write account secret files.
    for item in secrets.as_account_files(&genesis_state) {
        let AccountFileWithName { account_file, name } = item?;
        let accountpath = accounts_directory.join(name);
        // Do not override existing keys.
        fs_err::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&accountpath)
            .context("key file already exists")?;
        account_file.write(accountpath)?;
    }

    // Build the signed genesis block.
    let genesis_block =
        genesis_state.into_block().await.context("failed to build the genesis block")?;

    // Serialize and write the genesis block to disk.
    let block_bytes = genesis_block.inner().to_bytes();
    let genesis_block_path = genesis_block_directory.join(GENESIS_BLOCK_FILENAME);
    fs_err::write(&genesis_block_path, block_bytes).with_context(|| {
        format!("failed to write genesis block to {}", genesis_block_path.display())
    })?;

    Ok(())
}
