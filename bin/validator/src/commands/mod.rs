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
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "IP:PORT")]
        listen: std::net::SocketAddr,

        /// Socket address at which to serve the private administration API.
        #[arg(long = "admin.listen", env = ENV_ADMIN_LISTEN, value_name = "IP:PORT")]
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
            Self::Dkg(options) => dkg::run(options).await,
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
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use golden_core::{GoldenGroup, GoldenScalar, ParticipantIndex, SessionId};
    use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
    use golden_ehtdh1::{
        DecryptionShare,
        PublicKeySet,
        PublicShare,
        SecretShare,
        SetupContext,
        derive_context_session_id,
    };
    use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
    use miden_protocol::Word;
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::transaction::{TransactionId, TransactionInputs};
    use miden_protocol::utils::serde::{Deserializable, Serializable};
    use miden_testing::{Auth, MockChainBuilder};
    use rand_chacha_03::ChaCha20Rng;
    use rand_chacha_03::rand_core::SeedableRng;

    use super::*;

    type TestStorageGroup = Secp256k1GoldenGroup;

    const TEST_SIGNING_KEY_HEX: &str =
        "0101010101010101010101010101010101010101010101010101010101010101";
    const TEST_ENCRYPTION_KEY_HEX: &str =
        "0202020202020202020202020202020202020202020202020202020202020202";

    const BASE_START_ARGS: [&str; 8] = [
        "miden-validator",
        "start",
        "--listen",
        "127.0.0.1:50101",
        "--data-directory",
        "/tmp/validator-data",
        "--signing-key.hex",
        TEST_SIGNING_KEY_HEX,
    ];
    const ENCRYPTION_KEY_ARGS: [&str; 2] = ["--encryption-key.hex", TEST_ENCRYPTION_KEY_HEX];
    const STORAGE_KEY_ARGS: [&str; 8] = [
        "--storage-key.epoch",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "--storage-key.setup-context",
        "/tmp/setup.bin",
        "--storage-key.public-key-set",
        "/tmp/public.bin",
        "--storage-key.secret-share",
        "/tmp/secret.bin",
    ];

    fn parse_start(extra: &[&str]) -> Result<ValidatorCommand, clap::Error> {
        ValidatorCommand::try_parse_from(
            BASE_START_ARGS
                .iter()
                .copied()
                .chain(extra.iter().copied())
                .chain(STORAGE_KEY_ARGS.iter().copied()),
        )
    }

    fn test_operator_keys(epoch: u8, setup_marker: u8) -> Vec<GoldenOperatorKey> {
        let participants = [1, 2, 3].map(|value| ParticipantIndex::new(value).unwrap());
        let decryption_secret = Secp256k1Scalar::from_u64(11).unwrap();
        let decryption_coefficient = Secp256k1Scalar::from_u64(7).unwrap();
        let context_coefficient = Secp256k1Scalar::from_u64(13).unwrap();
        let mut public_shares = BTreeMap::new();
        let secret_shares = participants.map(|participant| {
            let point = participant.to_scalar::<Secp256k1Scalar>().unwrap();
            let decryption = decryption_secret.add(&decryption_coefficient.mul(&point));
            let context = context_coefficient.mul(&point);
            public_shares.insert(
                participant,
                PublicShare {
                    decryption: TestStorageGroup::mul_generator(&decryption),
                    context: TestStorageGroup::mul_generator(&context),
                },
            );
            SecretShare { participant, decryption, context }
        });
        let public_key_set = PublicKeySet::new(
            2,
            TestStorageGroup::mul_generator(&decryption_secret),
            public_shares,
        )
        .unwrap();
        let decryption_session_id = SessionId([2; 32]);
        let setup_context = SetupContext {
            backend_id: TestStorageGroup::BACKEND_ID.to_owned(),
            threshold: 2,
            registry_root: [1; 32],
            participants: participants.to_vec(),
            decryption_session_id,
            context_session_id: derive_context_session_id(decryption_session_id),
            decryption_transcript_root: [setup_marker; 32],
            context_transcript_root: [4; 32],
            epoch: [epoch; 32],
        };
        secret_shares
            .into_iter()
            .map(|secret_share| {
                GoldenOperatorKey::new(
                    StorageKeyEpoch::new([epoch; 32]),
                    setup_context.clone(),
                    public_key_set.clone(),
                    secret_share,
                )
                .unwrap()
            })
            .collect()
    }

    fn transaction_inputs() -> TransactionInputs {
        let mut builder = MockChainBuilder::new();
        let account = builder
            .add_existing_wallet(Auth::BasicAuth {
                auth_scheme: AuthScheme::Falcon512Poseidon2,
            })
            .unwrap();
        builder.build().unwrap().get_transaction_inputs(&account, &[], &[]).unwrap()
    }

    fn issue_error(record: &Path, output: &Path, operator_key: &GoldenOperatorKey) -> String {
        let error = issue_private_record_share::issue(record, output, operator_key).unwrap_err();
        format!("{error:#}")
    }

    fn assert_issue_error(
        record: &Path,
        output: &Path,
        operator_key: &GoldenOperatorKey,
        expected: &str,
    ) {
        let error = issue_error(record, output, operator_key);
        assert!(error.contains(expected), "expected {expected:?} in {error:?}");
    }

    fn issue_share_file(record: &Path, output: &Path, operator_key: &GoldenOperatorKey) -> Vec<u8> {
        issue_private_record_share::issue(record, output, operator_key).unwrap();
        fs_err::read(output).unwrap()
    }

    async fn store_private_record(
        writer: &miden_validator::db::ValidatorDbWriter,
        record: miden_validator::StoredPrivateRecord,
    ) {
        writer.insert_validated_private_transaction(record).await.unwrap();
    }

    async fn export_record_file(
        data_directory: &Path,
        encoded_transaction_id: &str,
        encoded_validator_id: &str,
        output: &Path,
    ) {
        export_private_record::export(PrivateRecordExportOptions {
            data_directory: data_directory.to_path_buf(),
            transaction_id: encoded_transaction_id.to_owned(),
            validator_id: encoded_validator_id.to_owned(),
            output: output.to_path_buf(),
        })
        .await
        .unwrap();
    }

    const BASE_GENESIS_ARGS: [&str; 6] = [
        "miden-validator",
        "genesis",
        "--genesis-block-directory",
        "/tmp/genesis",
        "--accounts-directory",
        "/tmp/accounts",
    ];

    fn parse_genesis(extra: &[&str]) -> Result<ValidatorCommand, clap::Error> {
        ValidatorCommand::try_parse_from(
            BASE_GENESIS_ARGS.iter().copied().chain(extra.iter().copied()),
        )
    }

    #[test]
    fn genesis_validator_keys_parse_from_repeated_flags() {
        let keys = [7u8, 8].map(|seed| {
            SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key should decode")
        });
        let hex_keys = keys.clone().map(|key| hex::encode(key.public_key().to_bytes()));
        let command =
            parse_genesis(&["--validator.key", &hex_keys[0], "--validator.key", &hex_keys[1]])
                .expect("genesis with explicit validator keys must parse");
        let ValidatorCommand::Genesis { validator_keys, .. } = command else {
            panic!("expected the genesis command");
        };
        assert_eq!(validator_keys, keys.map(|key| key.public_key()).to_vec());
    }

    #[test]
    fn genesis_requires_an_explicit_validator_set() {
        let Err(error) = parse_genesis(&[]) else {
            panic!("genesis without an explicit validator set must be rejected");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        let key = SigningKey::read_from_bytes(&[7; 32]).expect("test signing key should decode");
        let key_hex = hex::encode(key.public_key().to_bytes());
        parse_genesis(&["--config", "/tmp/genesis.toml", "--validator.key", &key_hex])
            .expect("--config with an explicit validator set must parse");
    }

    #[test]
    fn genesis_rejects_an_invalid_validator_key() {
        let Err(error) = parse_genesis(&["--validator.key", "not-hex"]) else {
            panic!("an invalid validator key must be rejected");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn encryption_key_is_required() {
        let Err(error) = parse_start(&[]) else {
            panic!("start without an encryption key must be rejected");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn signing_key_is_required() {
        let Err(error) = ValidatorCommand::try_parse_from(
            ["miden-validator", "start", "--listen", "127.0.0.1:50101"]
                .into_iter()
                .chain(["--data-directory", "/tmp/validator-data"])
                .chain(ENCRYPTION_KEY_ARGS)
                .chain(STORAGE_KEY_ARGS),
        ) else {
            panic!("start without a signing key must be rejected");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn admin_listener_is_opt_in() {
        let command =
            parse_start(&ENCRYPTION_KEY_ARGS).expect("start without an admin listener must parse");
        let ValidatorCommand::Start { admin_listen, .. } = command else {
            panic!("expected the start command");
        };
        assert_eq!(admin_listen, None);

        let command = parse_start(
            &[ENCRYPTION_KEY_ARGS.as_slice(), &["--admin.listen", "127.0.0.1:50102"]].concat(),
        )
        .expect("start with an admin listener must parse");
        let ValidatorCommand::Start { admin_listen, .. } = command else {
            panic!("expected the start command");
        };
        assert_eq!(admin_listen, Some("127.0.0.1:50102".parse().unwrap()));
    }

    #[test]
    fn encryption_key_kms_ciphertext_parses_alone() {
        let command = parse_start(&["--encryption-key.kms-ciphertext", "deadbeef"])
            .expect("KMS ciphertext without a hex key must parse");
        let ValidatorCommand::Start { encryption_key, .. } = command else {
            panic!("expected the start command");
        };
        assert_eq!(encryption_key.encryption_key_kms_ciphertext.as_deref(), Some("deadbeef"));
        assert_eq!(encryption_key.encryption_key, None);
    }

    #[test]
    fn encryption_key_hex_and_kms_ciphertext_conflict() {
        let result = parse_start(&[
            "--encryption-key.hex",
            TEST_ENCRYPTION_KEY_HEX,
            "--encryption-key.kms-ciphertext",
            "deadbeef",
        ]);
        let Err(error) = result else {
            panic!("hex key and KMS ciphertext together must be rejected");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn storage_key_is_required() {
        let Err(error) = ValidatorCommand::try_parse_from(
            BASE_START_ARGS.into_iter().chain(ENCRYPTION_KEY_ARGS),
        ) else {
            panic!("start without a storage key must fail");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn partial_storage_key_configuration_fails() {
        let Err(error) = ValidatorCommand::try_parse_from(
            BASE_START_ARGS.into_iter().chain(ENCRYPTION_KEY_ARGS).chain([
                "--storage-key.epoch",
                "0909090909090909090909090909090909090909090909090909090909090909",
            ]),
        ) else {
            panic!("a partial storage key must fail");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn keygen_command_parses() {
        let command = ValidatorCommand::try_parse_from(["miden-validator", "keygen"])
            .expect("the keygen command must parse");
        assert!(matches!(command, ValidatorCommand::Keygen));
    }

    #[test]
    fn private_record_share_command_parses() {
        let command = ValidatorCommand::try_parse_from([
            "miden-validator",
            "issue-private-record-share",
            "--record",
            "/tmp/record.bin",
            "--output",
            "/tmp/share.bin",
            "--storage-key.epoch",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "--storage-key.setup-context",
            "/tmp/setup.bin",
            "--storage-key.public-key-set",
            "/tmp/public.bin",
            "--storage-key.secret-share",
            "/tmp/secret.bin",
        ])
        .expect("the local share command must parse");

        let ValidatorCommand::IssuePrivateRecordShare(PrivateRecordShareOptions {
            record,
            output,
            ..
        }) = command
        else {
            panic!("expected the private record share command");
        };
        assert_eq!(record, PathBuf::from("/tmp/record.bin"));
        assert_eq!(output, PathBuf::from("/tmp/share.bin"));
    }

    #[test]
    fn private_record_export_command_parses() {
        let validator_id = SigningKey::read_from_bytes(&[7; 32]).unwrap().public_key().to_bytes();
        let command = ValidatorCommand::try_parse_from([
            "miden-validator",
            "export-private-record",
            "--data-directory",
            "/tmp/validator-data",
            "--transaction-id",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--validator-id",
            &hex::encode(validator_id),
            "--output",
            "/tmp/record.bin",
        ])
        .expect("the private record export command must parse");

        let ValidatorCommand::ExportPrivateRecord(PrivateRecordExportOptions {
            data_directory,
            transaction_id,
            output,
            ..
        }) = command
        else {
            panic!("expected the private record export command");
        };
        assert_eq!(data_directory, PathBuf::from("/tmp/validator-data"));
        assert_eq!(
            transaction_id,
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        assert_eq!(output, PathBuf::from("/tmp/record.bin"));
    }

    #[test]
    fn private_record_share_output_is_required() {
        let result = ValidatorCommand::try_parse_from([
            "miden-validator",
            "issue-private-record-share",
            "--record",
            "/tmp/record.bin",
            "--storage-key.epoch",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "--storage-key.setup-context",
            "/tmp/setup.bin",
            "--storage-key.public-key-set",
            "/tmp/public.bin",
            "--storage-key.secret-share",
            "/tmp/secret.bin",
        ]);

        let Err(error) = result else {
            panic!("share output must be explicit");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[tokio::test]
    async fn two_validators_issue_shares_for_third_validator_record() {
        let directory = tempfile::tempdir().unwrap();
        let writer = miden_validator::db::setup(directory.path().join("validator.sqlite3"))
            .await
            .unwrap();
        let operator_keys = test_operator_keys(9, 3);
        let validator_signers = [7u8, 8, 9].map(|seed| {
            SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key should decode")
        });
        let transaction_id = TransactionId::from_raw(Word::from([1u32, 2, 3, 4]));
        let inputs = transaction_inputs();
        let mut records = Vec::new();
        for (index, signer) in validator_signers.iter().enumerate() {
            let record_id =
                miden_validator::PrivateRecordId::new(transaction_id, &signer.public_key());
            let context = miden_validator::PrivateRecordContext::new(
                miden_validator::PrivateRecordChainId::new([5; 32]),
                operator_keys[index].key_epoch(),
                transaction_id,
            );
            let mut rng = ChaCha20Rng::from_seed([6 + index as u8; 32]);
            records.push(
                miden_validator::PrivateRecordSealer::from_operator_key(&operator_keys[index])
                    .seal(&mut rng, record_id, context, &inputs.to_bytes())
                    .unwrap(),
            );
        }
        assert_ne!(records[0].record_id(), records[1].record_id());
        assert_ne!(records[1].record_id(), records[2].record_id());
        assert_ne!(records[0].encrypted_record_key(), records[1].encrypted_record_key());
        assert_ne!(records[1].encrypted_record_key(), records[2].encrypted_record_key());

        let target = records.remove(2);
        store_private_record(&writer, target.clone()).await;
        let target_file = directory.path().join("target-record.bin");
        let encoded_transaction_id = hex::encode(transaction_id.to_bytes());
        let encoded_validator_id = hex::encode(target.record_id().validator_id());
        export_record_file(
            directory.path(),
            &encoded_transaction_id,
            &encoded_validator_id,
            &target_file,
        )
        .await;
        assert_eq!(
            miden_validator::StoredPrivateRecord::read_from_bytes(
                &fs_err::read(&target_file).unwrap()
            )
            .unwrap(),
            target,
        );

        let first_output = directory.path().join("share-1.bin");
        let second_output = directory.path().join("share-2.bin");
        let first_share = issue_share_file(&target_file, &first_output, &operator_keys[0]);
        let second_share = issue_share_file(&target_file, &second_output, &operator_keys[1]);
        let shares = [first_share, second_share];
        for share in &shares {
            let decoded = from_wire_bytes::<DecryptionShare<TestStorageGroup>>(share).unwrap();
            assert_eq!(to_wire_bytes(&decoded), *share);
        }
        let request = miden_validator::PrivateRecordShareRequest::for_record(&target);
        let opened = miden_validator::PrivateRecordCombiner::from_operator_key(&operator_keys[2])
            .unwrap()
            .open(&request, &target, &shares)
            .unwrap();
        assert_eq!(TransactionInputs::read_from_bytes(&opened).unwrap(), inputs);

        let wrong_epoch = test_operator_keys(10, 3).remove(0);
        assert_issue_error(&target_file, &first_output, &wrong_epoch, "key epoch does not match");

        let wrong_setup = test_operator_keys(9, 7).remove(0);
        assert_issue_error(&target_file, &first_output, &wrong_setup, "setup does not match");

        let missing_validator_id = hex::encode(validator_signers[0].public_key().to_bytes());
        let error = export_private_record::export(PrivateRecordExportOptions {
            data_directory: directory.path().to_path_buf(),
            transaction_id: encoded_transaction_id,
            validator_id: missing_validator_id,
            output: target_file,
        })
        .await;
        assert!(format!("{:#}", error.unwrap_err()).contains("was not found"));
    }
}
