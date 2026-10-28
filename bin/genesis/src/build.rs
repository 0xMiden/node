//! The `build` command: assembles the genesis block from the required accounts, the network
//! parameters and the validator set, and writes it with the generated account files.

use std::path::PathBuf;

use anyhow::Context;
use miden_node_store::genesis::config::{AccountFileWithName, GenesisConfig, GenesisInputs};
use miden_node_utils::fs::ensure_empty_directory;
use miden_objects::account_file::AccountFile;
use miden_protocol::block::{FeeParameters, ValidatorConfig};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Deserializable;

/// Name of the genesis block file written to the genesis block directory.
pub const GENESIS_BLOCK_FILE_NAME: &str = "genesis.dat";

const ENV_ACCOUNTS_CONFIG: &str = "MIDEN_GENESIS_ACCOUNTS_CONFIG";
const ENV_NATIVE_FAUCET: &str = "MIDEN_GENESIS_NATIVE_FAUCET";
const ENV_FUNDING_ACCOUNT: &str = "MIDEN_GENESIS_FUNDING_ACCOUNT";
const ENV_VERIFICATION_BASE_FEE: &str = "MIDEN_GENESIS_VERIFICATION_BASE_FEE";
const ENV_TIMESTAMP: &str = "MIDEN_GENESIS_TIMESTAMP";
const ENV_VALIDATOR_KEYS: &str = "MIDEN_GENESIS_VALIDATOR_KEYS";

// BUILD COMMAND
// ================================================================================================

/// Inputs used to build the genesis block.
#[derive(clap::Args, Debug)]
pub struct BuildCommand {
    /// Directory in which to write the genesis block.
    #[arg(long, value_name = "DIR")]
    pub genesis_block_directory: PathBuf,
    /// Directory in which to write generated account files.
    #[arg(long, value_name = "DIR")]
    pub accounts_directory: PathBuf,
    /// TOML file containing additional accounts.
    #[arg(long, env = ENV_ACCOUNTS_CONFIG, value_name = "FILE")]
    pub accounts_config: Option<PathBuf>,
    /// Account file for the native fungible faucet.
    #[arg(long, env = ENV_NATIVE_FAUCET, value_name = "FILE")]
    pub native_faucet: PathBuf,
    /// Account file for the public funding account.
    #[arg(long, env = ENV_FUNDING_ACCOUNT, value_name = "FILE")]
    pub funding_account: PathBuf,
    /// Verification base fee in base units of the native asset.
    #[arg(long, env = ENV_VERIFICATION_BASE_FEE)]
    pub verification_base_fee: u32,
    /// Genesis timestamp in seconds since the Unix epoch.
    #[arg(long, env = ENV_TIMESTAMP)]
    pub timestamp: u32,
    /// Hex-encoded public keys of all genesis validators. Repeat the flag for each validator. The
    /// environment variable accepts a comma-separated list.
    #[arg(
        long = "validator.key",
        env = ENV_VALIDATOR_KEYS,
        value_name = "VALIDATOR_PUBLIC_KEY",
        value_delimiter = ',',
        required = true,
        value_parser = parse_validator_public_key
    )]
    pub validator_keys: Vec<PublicKey>,
}

impl BuildCommand {
    /// Builds the unsigned genesis block and writes generated account files.
    pub fn execute(self) -> anyhow::Result<()> {
        let Self {
            genesis_block_directory,
            accounts_directory,
            accounts_config,
            native_faucet,
            funding_account,
            verification_base_fee,
            timestamp,
            validator_keys,
        } = self;
        for directory in [&genesis_block_directory, &accounts_directory] {
            ensure_empty_directory(directory)?;
        }

        let quorum = u16::try_from(validator_keys.len()).context("too many genesis validators")?;
        let validator_config = ValidatorConfig::new(validator_keys, quorum)
            .context("invalid genesis validator set")?;

        let config = accounts_config
            .as_ref()
            .map(|file_path| {
                GenesisConfig::read_toml_file(file_path).with_context(|| {
                    format!("failed to parse additional accounts from file {}", file_path.display())
                })
            })
            .transpose()?
            .unwrap_or_default();

        let native_faucet = AccountFile::read(&native_faucet)
            .with_context(|| {
                format!("failed to read native faucet from {}", native_faucet.display())
            })?
            .into_parts()
            .0;
        let funding_account = AccountFile::read(&funding_account)
            .with_context(|| {
                format!("failed to read funding account from {}", funding_account.display())
            })?
            .into_parts()
            .0;
        let (genesis_state, accounts) = config.into_state(GenesisInputs {
            native_faucet,
            funding_account,
            fee_parameters: FeeParameters::new(verification_base_fee),
            timestamp,
            validator_config,
        })?;

        for item in accounts.as_account_files(&genesis_state) {
            let AccountFileWithName { account_file, name } = item?;
            let account_path = accounts_directory.join(name);
            // Do not override existing account files.
            fs_err::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&account_path)
                .context("account file already exists")?;
            account_file.write(account_path)?;
        }

        let genesis_block =
            genesis_state.into_block().context("failed to build the genesis block")?;

        let genesis_block_path = genesis_block_directory.join(GENESIS_BLOCK_FILE_NAME);
        fs_err::write(&genesis_block_path, miden_node_persistence::encode(&genesis_block))
            .context("failed to write genesis block")?;

        println!("Genesis block written to {}.", genesis_block_path.display());
        println!();
        for account in genesis_block.inner().body().updated_accounts() {
            let account_id = account.account_id();
            let name = &accounts.names[&account_id];
            println!("{name} account id: {}", account_id.to_hex());
        }
        println!();
        println!("Seed each service's database with:");
        println!();
        for binary in ["miden-validator", "miden-node", "miden-ntx-builder"] {
            println!(
                "  {binary} bootstrap --data-directory <DIR> --genesis {}",
                genesis_block_path.display()
            );
        }

        Ok(())
    }
}

/// Parses a hex-encoded validator public key CLI argument.
fn parse_validator_public_key(hex_key: &str) -> Result<PublicKey, String> {
    let bytes = hex::decode(hex_key).map_err(|err| err.to_string())?;
    PublicKey::read_from_bytes(&bytes).map_err(|err| err.to_string())
}
