mod bootstrap;
mod start;

use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::logging::OpenTelemetry;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::utils::serde::Deserializable;
use miden_validator::{DataDirectory, ValidatorSigner};
use url::Url;

const ENV_DATA_DIRECTORY: &str = "MIDEN_VALIDATOR_DATA_DIRECTORY";
const ENV_LISTEN: &str = "MIDEN_VALIDATOR_LISTEN";
const ENV_STANDBY_URL: &str = "MIDEN_VALIDATOR_STANDBY_URL";
const ENV_KEY: &str = "MIDEN_VALIDATOR_KEY";
const ENV_KMS_KEY_ID: &str = "MIDEN_VALIDATOR_KMS_KEY_ID";
const ENV_GENESIS_CONFIG_FILE: &str = "MIDEN_VALIDATOR_GENESIS_CONFIG_FILE";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_VALIDATOR_SQLITE_CONNECTION_POOL_SIZE";

/// A predefined, insecure validator key for development purposes.
pub(crate) const INSECURE_KEY_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";

// VALIDATOR COMMAND
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub enum ValidatorCommand {
    /// Bootstraps the genesis block.
    ///
    /// Creates accounts from the genesis configuration, builds and signs the genesis block,
    /// and writes the signed block and account secret files to disk. Also initializes the
    /// validator's database with the genesis block as the chain tip.
    Bootstrap {
        /// Directory in which to write the genesis block file.
        #[arg(long, value_name = "DIR")]
        genesis_block_directory: PathBuf,
        /// Directory to write the account secret files (.mac) to.
        #[arg(long, value_name = "DIR")]
        accounts_directory: PathBuf,
        /// Directory in which to store the validator's database.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
        /// Maximum number of SQLite connections in the validator database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = miden_node_db::default_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,
        /// Use the given configuration file to construct the genesis state from.
        #[arg(long, env = ENV_GENESIS_CONFIG_FILE, value_name = "GENESIS_CONFIG")]
        genesis_config_file: Option<PathBuf>,
        /// Configuration for the Validator key used to sign the genesis block.
        #[command(flatten)]
        validator_key: ValidatorKey,
    },

    /// Applies pending validator database migrations.
    ///
    /// Cannot be run on an empty data directory; run `bootstrap` first.
    Migrate {
        /// Directory in which to store the validator's data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
    },

    /// Starts the validator component.
    Start {
        /// Socket address at which to serve the gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: std::net::SocketAddr,

        /// URL to the standby Validator instance that all requests are forwarded to.
        #[arg(long, env = ENV_STANDBY_URL, value_name = "URL")]
        standby_url: Option<Url>,

        #[command(flatten)]
        grpc_options: GrpcOptionsInternal,

        /// Maximum number of SQLite connections in the validator database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = miden_node_db::default_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,

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
            env = ENV_KEY,
            value_name = "VALIDATOR_KEY",
            default_value = INSECURE_KEY_HEX,
            group = "key"
        )]
        validator_key: String,

        /// Key ID for the KMS key used by validator to sign blocks.
        ///
        /// Cannot be used with `key.hex`.
        #[arg(
            long = "key.kms-id",
            env = ENV_KMS_KEY_ID,
            value_name = "VALIDATOR_KMS_KEY_ID",
            group = "key"
        )]
        kms_key_id: Option<String>,
    },
}

impl ValidatorCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        match self {
            Self::Bootstrap {
                genesis_block_directory,
                accounts_directory,
                data_directory,
                sqlite_connection_pool_size,
                genesis_config_file,
                validator_key,
            } => {
                bootstrap::bootstrap(
                    &genesis_block_directory,
                    &accounts_directory,
                    &data_directory,
                    sqlite_connection_pool_size,
                    genesis_config_file.as_ref(),
                    validator_key,
                )
                .await
            },
            Self::Migrate { data_directory } => {
                let data_dir = DataDirectory::load_server(data_directory)
                    .context("failed to load validator data directory")?;
                miden_validator::db::migrate(data_dir.database_path())
                    .context("failed to apply validator database migrations")?;
                Ok(())
            },
            Self::Start {
                listen,
                standby_url,
                grpc_options,
                validator_key,
                data_directory,
                kms_key_id,
                sqlite_connection_pool_size,
                ..
            } => {
                let address = listen;

                let signer = if let Some(kms_key_id) = kms_key_id {
                    ValidatorSigner::new_kms(kms_key_id).await?
                }else{
                    let signing_key = SigningKey::read_from_bytes(hex::decode(validator_key)?.as_ref())?;
                    ValidatorSigner::new_local(signing_key)
                };
                start::start(
                    address,
                    standby_url,
                    grpc_options,
                    signer,
                    data_directory,
                    sqlite_connection_pool_size,
                )
                .await
            },
        }
    }

    pub fn open_telemetry(&self) -> OpenTelemetry {
        match self {
            Self::Start { .. } => OpenTelemetry::from_env().with_name("validator"),
            Self::Bootstrap { .. } | Self::Migrate { .. } => OpenTelemetry::Disabled,
        }
    }
}

// VALIDATOR KEY
// ================================================================================================

/// Configuration for the Validator key used to sign blocks.
#[derive(clap::Args)]
#[group(required = false, multiple = false)]
pub struct ValidatorKey {
    /// Insecure, hex-encoded validator secret key for development and testing purposes.
    ///
    /// If not provided, a predefined key is used.
    ///
    /// Cannot be used with `key.kms-id`.
    #[arg(
        long = "key.hex",
        env = ENV_KEY,
        value_name = "VALIDATOR_KEY",
        default_value = INSECURE_KEY_HEX,
    )]
    pub validator_key: String,
    /// Key ID for the KMS key used by validator to sign blocks.
    ///
    /// Cannot be used with `key.hex`.
    #[arg(
        long = "key.kms-id",
        env = ENV_KMS_KEY_ID,
        value_name = "VALIDATOR_KMS_KEY_ID",
    )]
    pub validator_kms_key_id: Option<String>,
}

impl ValidatorKey {
    pub async fn into_signer(self) -> anyhow::Result<ValidatorSigner> {
        if let Some(kms_key_id) = self.validator_kms_key_id {
            Ok(ValidatorSigner::new_kms(kms_key_id).await?)
        } else {
            let signer = SigningKey::read_from_bytes(hex::decode(self.validator_key)?.as_ref())?;
            Ok(ValidatorSigner::new_local(signer))
        }
    }
}
