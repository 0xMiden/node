use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_store::genesis::config::{AccountFileWithName, GenesisConfig};
use miden_node_utils::fs::ensure_empty_directory;
use miden_protocol::block::ValidatorConfig;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Serializable;

/// Name of the genesis block file written to the genesis block directory.
const GENESIS_BLOCK_FILE_NAME: &str = "genesis.dat";

/// Runs the `genesis` command: builds the genesis block from a genesis configuration.
///
/// Builds the genesis state from the given configuration — or from [`GenesisConfig::default`]
/// when `None`, as in local development where the default state suffices — writes the account
/// secret files, and writes the genesis block file.
///
/// The genesis block is not signed: its header commits to the full validator set, taken from the
/// given `validator_keys` public keys, and that set is required to sign every block after genesis.
/// Building the genesis block therefore needs no signing access to any validator's key.
///
/// Every validator — including the operator who ran this command — then seeds its database from
/// the written genesis block file via the `bootstrap` command.
pub fn generate(
    genesis_block_directory: &Path,
    accounts_directory: &Path,
    genesis_config: Option<&PathBuf>,
    validator_keys: Vec<PublicKey>,
) -> anyhow::Result<()> {
    for directory in [genesis_block_directory, accounts_directory] {
        ensure_empty_directory(directory)?;
    }

    let quorum = u16::try_from(validator_keys.len()).context("too many genesis validators")?;
    let validator_config =
        ValidatorConfig::new(validator_keys, quorum).context("invalid genesis validator set")?;

    let config = genesis_config
        .map(|file_path| {
            GenesisConfig::read_toml_file(file_path).with_context(|| {
                format!("failed to parse genesis config from file {}", file_path.display())
            })
        })
        .transpose()?
        .unwrap_or_default();

    let (genesis_state, secrets) = config.into_state(validator_config)?;

    for item in secrets.as_account_files(&genesis_state) {
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

    let native_faucet_id = genesis_state.protocol_config.fee_asset_id().faucet_id();

    let genesis_block = genesis_state.into_block().context("failed to build the genesis block")?;

    let genesis_block_path = genesis_block_directory.join(GENESIS_BLOCK_FILE_NAME);
    fs_err::write(&genesis_block_path, genesis_block.inner().to_bytes())
        .context("failed to write genesis block")?;

    println!("Genesis block written to {}.", genesis_block_path.display());
    println!();
    println!("Native faucet account id: {}", native_faucet_id.to_hex());
    println!();
    println!("Seed each validator's database with:");
    println!();
    println!(
        "  miden-validator bootstrap --data-directory <DIR> --genesis {}",
        genesis_block_path.display()
    );

    Ok(())
}
