mod bootstrap;
mod start;

use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::Parser;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::utils::serde::Deserializable;
use miden_validator::ValidatorSigner;

const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";
const ENV_LISTEN: &str = "MIDEN_NODE_VALIDATOR_LISTEN";
const ENV_KEY: &str = "MIDEN_NODE_VALIDATOR_KEY";
const ENV_KMS_KEY_ID: &str = "MIDEN_NODE_VALIDATOR_KMS_KEY_ID";
const ENV_ENABLE_OTEL: &str = "MIDEN_NODE_ENABLE_OTEL";
const ENV_GENESIS_CONFIG_FILE: &str = "MIDEN_NODE_VALIDATOR_GENESIS_CONFIG_FILE";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_NODE_VALIDATOR_SQLITE_CONNECTION_POOL_SIZE";

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

    /// Starts the validator component.
    Start {
        /// Socket address at which to serve the gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: std::net::SocketAddr,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

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
            Self::Start {
                listen,
                grpc_options,
                validator_key,
                data_directory,
                kms_key_id,
                sqlite_connection_pool_size,
                ..
            } => {
                let address = listen;

                if let Some(kms_key_id) = kms_key_id {
                    let signer = ValidatorSigner::new_kms(kms_key_id).await?;
                    start::start(
                        address,
                        grpc_options,
                        signer,
                        data_directory,
                        sqlite_connection_pool_size,
                    )
                    .await
                } else {
                    let signer = SecretKey::read_from_bytes(hex::decode(validator_key)?.as_ref())?;
                    let signer = ValidatorSigner::new_local(signer);
                    start::start(
                        address,
                        grpc_options,
                        signer,
                        data_directory,
                        sqlite_connection_pool_size,
                    )
                    .await
                }
            },
        }
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        match self {
            Self::Start { enable_otel, .. } => *enable_otel,
            Self::Bootstrap { .. } => false,
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
    /// Cannot be used with `validator.key.kms-id`.
    #[arg(
        long = "validator.key.hex",
        env = ENV_KEY,
        value_name = "VALIDATOR_KEY",
        default_value = INSECURE_KEY_HEX,
    )]
    pub validator_key: String,
    /// Key ID for the KMS key used by validator to sign blocks.
    ///
    /// Cannot be used with `validator.key.hex`.
    #[arg(
        long = "validator.key.kms-id",
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
            let signer = SecretKey::read_from_bytes(hex::decode(self.validator_key)?.as_ref())?;
            Ok(ValidatorSigner::new_local(signer))
        }
    }
}
