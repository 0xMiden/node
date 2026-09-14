mod bootstrap;
mod dkg;
mod export_private_record;
mod genesis;
mod issue_private_record_share;
mod start;

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use clap::Parser;
use miden_node_tracing::{OpenTelemetry, info};
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SigningKey};
use miden_protocol::crypto::dsa::eddsa_25519_sha512::KeyExchangeKey;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_validator::{
    DataDirectory,
    EncodedGoldenOperatorKey,
    GoldenOperatorKey,
    LocalX25519TransactionInputDecrypter,
    StorageKeyEpoch,
    TransactionInputDecrypter,
    ValidatorSigner,
};

const ENV_DATA_DIRECTORY: &str = "MIDEN_VALIDATOR_DATA_DIRECTORY";
const ENV_LISTEN: &str = "MIDEN_VALIDATOR_LISTEN";
const ENV_ADMIN_LISTEN: &str = "MIDEN_VALIDATOR_ADMIN_LISTEN";
const ENV_SIGNING_KEY: &str = "MIDEN_VALIDATOR_SIGNING_KEY";
const ENV_SIGNING_KEY_KMS_ID: &str = "MIDEN_VALIDATOR_SIGNING_KEY_KMS_ID";
const ENV_ENCRYPTION_KEY: &str = "MIDEN_VALIDATOR_ENCRYPTION_KEY";
const ENV_ENCRYPTION_KEY_KMS_CIPHERTEXT: &str = "MIDEN_VALIDATOR_ENCRYPTION_KEY_KMS_CIPHERTEXT";
const ENV_GENESIS_CONFIG: &str = "MIDEN_VALIDATOR_GENESIS_CONFIG";
const ENV_GENESIS_VALIDATOR_KEYS: &str = "MIDEN_VALIDATOR_GENESIS_VALIDATOR_KEYS";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_VALIDATOR_SQLITE_CONNECTION_POOL_SIZE";
const ENV_STORAGE_KEY_EPOCH: &str = "MIDEN_VALIDATOR_STORAGE_KEY_EPOCH";
const ENV_STORAGE_KEY_PUBLIC_SET: &str = "MIDEN_VALIDATOR_STORAGE_KEY_PUBLIC_SET";
const ENV_STORAGE_KEY_SECRET_SHARE: &str = "MIDEN_VALIDATOR_STORAGE_KEY_SECRET_SHARE";
const ENV_STORAGE_KEY_SETUP_CONTEXT: &str = "MIDEN_VALIDATOR_STORAGE_KEY_SETUP_CONTEXT";

// VALIDATOR COMMAND
// ================================================================================================

/// Local inputs for issuing one private-record share.
#[derive(clap::Args)]
pub struct PrivateRecordShareOptions {
    /// Canonical private-record bundle for which to issue a share.
    #[arg(long, value_name = "FILE")]
    record: PathBuf,

    /// File that receives the canonical share bytes.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,

    /// Canonical storage key material for this validator.
    #[command(flatten)]
    storage_key: ValidatorStorageKey,
}

/// Local inputs for exporting one private-record bundle.
#[derive(clap::Args)]
pub struct PrivateRecordExportOptions {
    /// Directory containing the validator database that owns the record.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    /// Hex-encoded transaction identifier.
    #[arg(long, value_name = "TRANSACTION_ID")]
    transaction_id: String,

    /// Hex-encoded signing public key of the validator that produced the record.
    #[arg(long, value_name = "VALIDATOR_ID")]
    validator_id: String,

    /// File that receives the canonical private-record bundle.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub enum ValidatorCommand {
    /// Builds the genesis block from a genesis configuration.
    ///
    /// Creates accounts from the genesis configuration, builds the genesis block, and writes the
    /// block and account secret files to disk.
    ///
    /// The genesis block is the chain's trust root and is not signed: its header commits to the
    /// full validator set — the public keys passed via `--validator.key` — and that set is
    /// required to sign every block after genesis. Building the genesis block needs no signing
    /// access to any validator's key, so one operator — who need not be a validator — runs this
    /// once and distributes the genesis block file.
    ///
    /// Every validator then seeds its database from the genesis block file with `bootstrap`.
    Genesis {
        /// Directory in which to write the genesis block file.
        #[arg(long, value_name = "DIR")]
        genesis_block_directory: PathBuf,
        /// Directory to write the account secret files (.mac) to.
        #[arg(long, value_name = "DIR")]
        accounts_directory: PathBuf,
        /// Use the given configuration file to construct the genesis state from.
        ///
        /// If not provided, the built-in development configuration is used.
        #[arg(long = "config", env = ENV_GENESIS_CONFIG, value_name = "GENESIS_CONFIG")]
        genesis_config_file: Option<PathBuf>,
        /// Hex-encoded public keys of the genesis validator set, committed to by the genesis
        /// header.
        ///
        /// Repeat the flag once per validator (`--validator.key <KEY> --validator.key <KEY>`);
        /// the environment variable takes a comma-separated list. The genesis block itself is not
        /// signed; the committed set must sign every block after genesis.
        ///
        /// Each validator operator prints their public key with `pubkey`; `keygen` generates a
        /// fresh key-pair for local networks.
        #[arg(
            long = "validator.key",
            env = ENV_GENESIS_VALIDATOR_KEYS,
            value_name = "VALIDATOR_PUBLIC_KEY",
            value_delimiter = ',',
            required = true,
            value_parser = parse_validator_public_key
        )]
        validator_keys: Vec<PublicKey>,
    },

    /// Seeds this validator's database from a genesis block file.
    ///
    /// Every validator runs this once before `start`, against the genesis block file produced by
    /// the `genesis` command. The genesis block is the chain's trust root and carries no
    /// signatures; the file must come from a trusted source.
    Bootstrap {
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
        /// Genesis block file to seed this validator's database from.
        #[arg(long = "genesis", value_name = "FILE")]
        genesis_block_file: PathBuf,
    },

    /// Prints the hex-encoded public key for the configured validator signing key.
    ///
    /// Every validator operator runs this and sends the printed key to whoever runs the `genesis`
    /// command, which commits the full set to the genesis header via its `--validator.key` flags.
    Pubkey {
        #[command(flatten)]
        signing_key: ValidatorSigningKey,
    },

    /// Generates a validator signing key-pair and a shared transaction encryption key.
    ///
    /// Prints hex-encoded key material to stdout: the signing secret key (`start
    /// --signing-key.hex`), its public key (`genesis --validator.key`), and a transaction
    /// encryption key (`start --encryption-key.hex`), which must be shared by every validator
    /// in the set.
    ///
    /// Intended for local networks; production deployments should prefer KMS-backed keys
    /// (`--signing-key.kms-id`, `--encryption-key.kms-ciphertext`).
    Keygen,

    /// Applies pending validator database migrations.
    ///
    /// Cannot be run on an empty data directory; run `bootstrap` first.
    Migrate {
        /// Directory in which to store the validator's data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
    },

    /// Runs the storage-key setup ceremony.
    Dkg(dkg::DkgOptions),

    /// Issues this validator's decryption share for one stored private record.
    IssuePrivateRecordShare(PrivateRecordShareOptions),

    /// Exports one validator-qualified private-record bundle.
    ExportPrivateRecord(PrivateRecordExportOptions),

    /// Starts the validator component.
    Start {
        /// Socket address at which to serve the gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: std::net::SocketAddr,

        /// Socket address at which to serve the private administration API.
        #[arg(long = "admin.listen", env = ENV_ADMIN_LISTEN, value_name = "LISTEN")]
        admin_listen: Option<std::net::SocketAddr>,

        #[command(flatten)]
        grpc_options: GrpcOptions,

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

        /// Signing key used by the validator to sign blocks.
        #[command(flatten)]
        signing_key: ValidatorSigningKey,

        /// Shared transaction encryption key.
        #[command(flatten)]
        encryption_key: ValidatorEncryptionKey,

        /// Canonical Storage key material provisioned after setup.
        #[command(flatten)]
        storage_key: ValidatorStorageKey,
    },
}

impl ValidatorCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        match self {
            Self::Genesis {
                genesis_block_directory,
                accounts_directory,
                genesis_config_file,
                validator_keys,
            } => genesis::generate(
                &genesis_block_directory,
                &accounts_directory,
                genesis_config_file.as_ref(),
                validator_keys,
            ),
            Self::Bootstrap {
                data_directory,
                sqlite_connection_pool_size,
                genesis_block_file,
            } => {
                bootstrap::bootstrap(
                    &data_directory,
                    sqlite_connection_pool_size,
                    &genesis_block_file,
                )
                .await
            },
            Self::Pubkey { signing_key } => {
                let signer = signing_key.into_signer().await?;
                println!("{}", hex::encode(signer.public_key().to_bytes()));
                Ok(())
            },
            Self::Keygen => {
                let signing_key = SigningKey::new();
                let encryption_key = KeyExchangeKey::new();
                println!("signing-key: {}", hex::encode(signing_key.to_bytes()));
                println!("validator-key: {}", hex::encode(signing_key.public_key().to_bytes()));
                println!("encryption-key: {}", hex::encode(encryption_key.to_bytes()));
                Ok(())
            },
            Self::Migrate { data_directory } => {
                let data_dir = DataDirectory::load(data_directory)
                    .context("failed to load validator data directory")?;
                miden_validator::db::migrate(data_dir.database_path())
                    .context("failed to apply validator database migrations")?;
                Ok(())
            },
            Self::Dkg(options) => Box::pin(dkg::run(options)).await,
            Self::IssuePrivateRecordShare(options) => {
                issue_private_record_share::issue_from_options(options)
            },
            Self::ExportPrivateRecord(options) => export_private_record::export(options).await,
            Self::Start {
                listen,
                admin_listen,
                grpc_options,
                signing_key,
                data_directory,
                sqlite_connection_pool_size,
                encryption_key,
                storage_key,
            } => {
                let address = listen;
                let operator_key = storage_key.load()?;
                info!(
                    target: miden_validator::LOG_TARGET,
                    "Starting validator",
                    service.name = "miden-validator",
                    service.version = env!("CARGO_PKG_VERSION"),
                    validator.listen = address.to_string(),
                    validator.admin_listen = admin_listen.map_or_else(
                        || "disabled".to_owned(),
                        |address| address.to_string(),
                    ),
                    data.directory = data_directory.as_path(),
                    validator.signer =
                        if signing_key.signing_key_kms_id.is_some() { "kms" } else { "local" },
                    db.sqlite.connection_pool_size = sqlite_connection_pool_size.get()
                );

                let decrypter = encryption_key.into_decrypter().await?;

                let signer = signing_key.into_signer().await?;

                start::start(
                    address,
                    admin_listen,
                    grpc_options,
                    start::ValidatorKeys { signer, decrypter, operator_key },
                    data_directory,
                    sqlite_connection_pool_size,
                    shutdown,
                )
                .await
            },
        }
    }

    pub fn open_telemetry(&self) -> OpenTelemetry {
        match self {
            Self::Start { .. } => OpenTelemetry::from_env().with_name("validator"),
            Self::Genesis { .. }
            | Self::Bootstrap { .. }
            | Self::Pubkey { .. }
            | Self::Keygen
            | Self::Dkg(_)
            | Self::ExportPrivateRecord(_)
            | Self::IssuePrivateRecordShare(_)
            | Self::Migrate { .. } => OpenTelemetry::Disabled,
        }
    }
}

/// Parses a hex-encoded validator public key CLI argument.
fn parse_validator_public_key(hex_key: &str) -> Result<PublicKey, String> {
    let bytes = hex::decode(hex_key).map_err(|err| err.to_string())?;
    PublicKey::read_from_bytes(&bytes).map_err(|err| err.to_string())
}

/// Configuration for the shared transaction encryption key.
#[derive(clap::Args)]
#[group(required = true, multiple = false)]
pub struct ValidatorEncryptionKey {
    /// Hex-encoded shared secret of the transaction encryption key.
    ///
    /// Unlike the per-validator signing key, this value must be identical across every
    /// validator in the set. `keygen` generates a fresh key for local networks.
    ///
    /// Cannot be used with `encryption-key.kms-ciphertext`.
    #[arg(
        long = "encryption-key.hex",
        env = ENV_ENCRYPTION_KEY,
        value_name = "VALIDATOR_ENCRYPTION_KEY"
    )]
    encryption_key: Option<String>,
    /// Base64-encoded KMS ciphertext of the shared transaction encryption key, as returned
    /// by `kms:Encrypt`.
    ///
    /// The wrapped key material is recovered at startup with `kms:Decrypt`. The ciphertext
    /// must have been produced by `kms:Encrypt` under a symmetric KMS key, whose ID is
    /// embedded in the ciphertext blob.
    ///
    /// Cannot be used with `encryption-key.hex`.
    #[arg(
        long = "encryption-key.kms-ciphertext",
        env = ENV_ENCRYPTION_KEY_KMS_CIPHERTEXT,
        value_name = "VALIDATOR_ENCRYPTION_KEY_KMS_CIPHERTEXT"
    )]
    encryption_key_kms_ciphertext: Option<String>,
}

impl ValidatorEncryptionKey {
    /// Builds the transaction input decrypter from the configured shared encryption key: either the
    /// KMS-wrapped ciphertext, or the hex-encoded key material.
    async fn into_decrypter(self) -> anyhow::Result<Arc<dyn TransactionInputDecrypter>> {
        let encryption_key_bytes = if let Some(ciphertext) = self.encryption_key_kms_ciphertext {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(ciphertext)
                .context("failed to decode the encryption key KMS ciphertext base64")?;
            miden_validator::decrypt_key_material(ciphertext)
                .await
                .context("failed to decrypt the encryption key with KMS")?
        } else {
            let encryption_key = self
                .encryption_key
                .expect("clap guarantees exactly one encryption key source is set");
            hex::decode(encryption_key).context("failed to decode the encryption key hex")?
        };
        let encryption_key = KeyExchangeKey::read_from_bytes(&encryption_key_bytes)
            .context("failed to construct the encryption key")?;
        Ok(Arc::new(LocalX25519TransactionInputDecrypter::new(encryption_key)))
    }
}

/// Canonical files needed to restore one validator storage key share.
#[derive(clap::Args)]
pub struct ValidatorStorageKey {
    /// Hex-encoded 32-byte storage key epoch.
    #[arg(
        long = "storage-key.epoch",
        env = ENV_STORAGE_KEY_EPOCH,
        value_name = "STORAGE_KEY_EPOCH"
    )]
    key_epoch: String,
    /// File containing canonical `SetupContext` bytes.
    #[arg(
        long = "storage-key.setup-context",
        env = ENV_STORAGE_KEY_SETUP_CONTEXT,
        value_name = "FILE"
    )]
    setup_context: PathBuf,
    /// File containing canonical `PublicKeySet` bytes.
    #[arg(
        long = "storage-key.public-key-set",
        env = ENV_STORAGE_KEY_PUBLIC_SET,
        value_name = "FILE"
    )]
    public_key_set: PathBuf,
    /// File containing this operator's canonical `SecretShare` bytes.
    #[arg(
        long = "storage-key.secret-share",
        env = ENV_STORAGE_KEY_SECRET_SHARE,
        value_name = "FILE"
    )]
    secret_share: PathBuf,
}

impl ValidatorStorageKey {
    fn load(self) -> anyhow::Result<GoldenOperatorKey> {
        let key_epoch =
            hex::decode(self.key_epoch).context("failed to decode storage key epoch")?;
        let key_epoch = key_epoch.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("storage key epoch has {} bytes, expected 32", bytes.len())
        })?;
        let operator_key = EncodedGoldenOperatorKey::new(
            StorageKeyEpoch::new(key_epoch),
            fs_err::read(&self.setup_context).with_context(|| {
                format!(
                    "failed to read storage key setup context from {}",
                    self.setup_context.display()
                )
            })?,
            fs_err::read(&self.public_key_set).with_context(|| {
                format!(
                    "failed to read storage key public key set from {}",
                    self.public_key_set.display()
                )
            })?,
            fs_err::read(&self.secret_share).with_context(|| {
                format!(
                    "failed to read storage key secret share from {}",
                    self.secret_share.display()
                )
            })?,
        )
        .decode()
        .context("failed to validate storage key material")?;
        Ok(operator_key)
    }
}

// VALIDATOR SIGNING KEY
// ================================================================================================

/// Configuration for the validator signing key used to sign blocks.
#[derive(clap::Args)]
#[group(required = true, multiple = false)]
pub struct ValidatorSigningKey {
    /// Hex-encoded validator secret key.
    ///
    /// `keygen` generates a fresh key-pair for local networks; production deployments should
    /// prefer `signing-key.kms-id`.
    ///
    /// Cannot be used with `signing-key.kms-id`.
    #[arg(
        long = "signing-key.hex",
        env = ENV_SIGNING_KEY,
        value_name = "VALIDATOR_SIGNING_KEY",
    )]
    pub signing_key: Option<String>,
    /// Key ID for the KMS key used by validator to sign blocks.
    ///
    /// Cannot be used with `signing-key.hex`.
    #[arg(
        long = "signing-key.kms-id",
        env = ENV_SIGNING_KEY_KMS_ID,
        value_name = "VALIDATOR_SIGNING_KEY_KMS_ID",
    )]
    pub signing_key_kms_id: Option<String>,
}

impl ValidatorSigningKey {
    pub async fn into_signer(self) -> anyhow::Result<ValidatorSigner> {
        if let Some(kms_key_id) = self.signing_key_kms_id {
            Ok(ValidatorSigner::new_kms(kms_key_id).await?)
        } else {
            let signing_key =
                self.signing_key.expect("clap guarantees exactly one signing key source is set");
            let signer = SigningKey::read_from_bytes(hex::decode(signing_key)?.as_ref())?;
            Ok(ValidatorSigner::new_local(signer))
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests;
