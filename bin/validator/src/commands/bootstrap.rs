use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_store::genesis::config::{AccountFileWithName, GenesisConfig};
use miden_node_utils::fs::ensure_empty_directory;
use miden_protocol::utils::serde::Serializable;
use miden_validator::ValidatorSigner;

use super::ValidatorKey;

const GENESIS_BLOCK_FILENAME: &str = "genesis.dat";

// Bootstraps the validator component.
pub async fn bootstrap(
    genesis_block_directory: &Path,
    accounts_directory: &Path,
    data_directory: &Path,
    sqlite_connection_pool_size: NonZeroUsize,
    genesis_config: Option<&PathBuf>,
    validator_key: ValidatorKey,
) -> anyhow::Result<()> {
    let config = genesis_config
        .map(|file_path| {
            GenesisConfig::read_toml_file(file_path).with_context(|| {
                format!("failed to parse genesis config from file {}", file_path.display())
            })
        })
        .transpose()?
        .unwrap_or_default();

    for directory in [accounts_directory, genesis_block_directory, data_directory] {
        ensure_empty_directory(directory)?;
    }

    let signer = validator_key.into_signer().await?;
    build_and_write_genesis(
        config,
        signer,
        accounts_directory,
        genesis_block_directory,
        data_directory,
        sqlite_connection_pool_size,
    )
    .await
}

/// Builds the genesis state, writes account secret files, signs the genesis block, writes it
/// to disk, and initializes the validator's database with the genesis block as the chain tip.
async fn build_and_write_genesis(
    config: GenesisConfig,
    signer: ValidatorSigner,
    accounts_directory: &Path,
    genesis_block_directory: &Path,
    data_directory: &Path,
    sqlite_connection_pool_size: NonZeroUsize,
) -> anyhow::Result<()> {
    let (genesis_state, secrets) = config.into_state(signer.public_key())?;

    for item in secrets.as_account_files(&genesis_state) {
        let AccountFileWithName { account_file, name } = item?;
        let account_path = accounts_directory.join(name);
        // Do not override existing keys.
        fs_err::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&account_path)
            .context("key file already exists")?;
        account_file.write(account_path)?;
    }

    let unsigned_genesis_block = genesis_state
        .into_unsigned_block()
        .context("failed to build the unsigned genesis block")?;
    let signature = signer
        .sign(unsigned_genesis_block.header())
        .await
        .context("failed to sign the genesis block")?;
    let genesis_block = unsigned_genesis_block
        .into_block(signature)
        .context("failed to build the genesis block")?;

    let block_bytes = genesis_block.inner().to_bytes();
    let genesis_block_path = genesis_block_directory.join(GENESIS_BLOCK_FILENAME);
    fs_err::write(&genesis_block_path, block_bytes).context("failed to write genesis block")?;

    let (genesis_header, ..) = genesis_block.into_inner().into_parts();
    let db = miden_validator::db::load_with_pool_size(
        data_directory.join("validator.sqlite3"),
        sqlite_connection_pool_size,
    )
    .await
    .context("failed to initialize validator database during bootstrap")?;
    db.transact("upsert_block_header", move |conn| {
        miden_validator::db::upsert_block_header(conn, &genesis_header)
    })
    .await
    .context("failed to persist genesis block header as chain tip")?;

    Ok(())
}
