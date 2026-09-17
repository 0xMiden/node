use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::ArgGroup;
use miden_node_store::allowlist::AccountAllowlist;
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{DataDirectory, Db, State};
use miden_node_tracing::info;
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::genesis::{OfficialNetwork, fetch_genesis_block, read_genesis_block};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{AccountBuilder, AccountFile, AccountType};
use miden_protocol::utils::serde::Serializable;
use miden_standards::account::auth::AuthTxFeeCollector;
use miden_standards::account::wallets::BasicWallet;

use super::ENV_DATA_DIRECTORY;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_saves_a_new_collector_and_preserves_its_signing_key() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let directory = DataDirectory::load(directory.path().to_path_buf())?;
        create_collection_account(&directory)?;
        let path = directory.batch_builder_collection_account_path();
        let account_file = AccountFile::read(&path)?;
        assert!(account_file.account.is_new());
        assert!(account_file.account.is_public());
        assert!(account_file.account.vault().is_empty());
        assert_eq!(account_file.auth_secret_keys.len(), 1);
        assert_eq!(
            account_file.account.storage().get_item(AuthTxFeeCollector::public_key_slot())?,
            miden_protocol::Word::from(
                account_file.auth_secret_keys[0].public_key().to_commitment()
            ),
        );

        let contents = fs_err::read(&path)?;
        assert!(create_collection_account(&directory).is_err());
        assert_eq!(fs_err::read(&path)?, contents);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs_err::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        Ok(())
    }
}

// BOOTSTRAP
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
#[command(group(
    ArgGroup::new("genesis_block_source")
        .required(true)
        .multiple(false)
        .args(["genesis_block_file", "network"])
))]
pub struct BootstrapCommand {
    /// Directory to initialize with the node's local data storage.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    /// Bootstrap from a trusted genesis block file.
    #[arg(long = "genesis", value_name = "FILE")]
    genesis_block_file: Option<PathBuf>,

    /// Bootstrap for an official Miden network.
    #[arg(long, value_enum, value_name = "NETWORK")]
    network: Option<OfficialNetwork>,
}

impl BootstrapCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        info!(
            target: crate::LOG_TARGET,
            "Bootstrapping node",
            service.name = "miden-node",
            service.version = env!("CARGO_PKG_VERSION"),
            genesis.source.kind =
                if self.genesis_block_file.is_some() { "file" } else { "network" },
            genesis.source = self.genesis_block_file.as_ref().map_or_else(
                || self.network.map_or_else(
                    || "custom".to_owned(),
                    |network| network.to_string(),
                ),
                |path| path.display().to_string(),
            ),
            data.directory = self.data_directory.as_path()
        );
        ensure_empty_directory(&self.data_directory)?;
        let genesis_block =
            read_bootstrap_genesis_block(self.genesis_block_file.as_deref(), self.network).await?;
        let genesis_commitment = genesis_block.inner().header().commitment();
        State::bootstrap(genesis_block, &self.data_directory)?;
        create_collection_account(&DataDirectory::load(self.data_directory.clone())?)
            .context("failed to create the batch builder collection account")?;
        info!(
            target: crate::LOG_TARGET,
            "Node bootstrap complete",
            genesis.commitment = genesis_commitment,
            data.directory = self.data_directory.as_path()
        );
        Ok(())
    }
}

/// Saves the collector and its signing key without registering the account on-chain.
fn create_collection_account(directory: &DataDirectory) -> anyhow::Result<()> {
    let secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let account = AccountBuilder::new(rand::random())
        .account_type(AccountType::Public)
        .with_component(AuthTxFeeCollector::from_public_key(secret_key.public_key()))
        .with_component(BasicWallet)
        .build()?;
    let account_file = AccountFile::new(account, vec![secret_key]);
    let mut options = fs_err::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(directory.batch_builder_collection_account_path())?;
    file.write_all(&account_file.to_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Reads the genesis block from the configured source and validates it.
async fn read_bootstrap_genesis_block(
    genesis_block_file: Option<&Path>,
    network: Option<OfficialNetwork>,
) -> anyhow::Result<GenesisBlock> {
    match (genesis_block_file, network) {
        (Some(path), None) => read_genesis_block(path),
        (None, Some(network)) => fetch_genesis_block(network).await,
        _ => unreachable!("clap requires exactly one genesis block source"),
    }
}

// MIGRATE
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct MigrateCommand {
    /// Directory containing the node's local data storage.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,
}

impl MigrateCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let data_directory =
            DataDirectory::load(self.data_directory.clone()).with_context(|| {
                format!("failed to load data directory at {}", self.data_directory.display())
            })?;

        Db::migrate(data_directory.database_path())
            .context("failed to apply store database migrations")?;

        // Only sequencer startup creates this optional database. Migration must also work for full
        // nodes that do not have it.
        let allowlist_path = data_directory.allowlist_database_path();
        if fs_err::exists(&allowlist_path).context("failed to check account allowlist database")? {
            AccountAllowlist::migrate(allowlist_path)
                .context("failed to apply account allowlist migrations")?;
        }

        Ok(())
    }
}
