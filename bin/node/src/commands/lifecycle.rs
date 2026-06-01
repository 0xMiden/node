use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::ArgGroup;
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{DataDirectory, Db, State};
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::genesis::{
    OfficialNetwork,
    fetch_signed_genesis_block,
    read_signed_genesis_block,
};
use miden_protocol::block::SignedBlock;

use super::ENV_DATA_DIRECTORY;

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
    #[arg(long = "file", value_name = "FILE")]
    genesis_block_file: Option<PathBuf>,

    /// Bootstrap for an official Miden network.
    #[arg(long, value_enum, value_name = "NETWORK")]
    network: Option<OfficialNetwork>,
}

impl BootstrapCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        ensure_empty_directory(&self.data_directory)?;
        let signed_block =
            read_bootstrap_genesis_block(self.genesis_block_file.as_deref(), self.network).await?;
        bootstrap_store(&self.data_directory, signed_block)
    }
}

async fn read_bootstrap_genesis_block(
    genesis_block_file: Option<&Path>,
    network: Option<OfficialNetwork>,
) -> anyhow::Result<SignedBlock> {
    match (genesis_block_file, network) {
        (Some(path), None) => read_signed_genesis_block(path),
        (None, Some(network)) => fetch_signed_genesis_block(network).await,
        _ => unreachable!("clap requires exactly one genesis block source"),
    }
}

/// Validates a signed genesis block and bootstraps the store.
pub fn bootstrap_store(data_directory: &Path, signed_block: SignedBlock) -> anyhow::Result<()> {
    let genesis_block =
        GenesisBlock::try_from(signed_block).context("genesis block validation failed")?;

    State::bootstrap(genesis_block, data_directory)
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
    pub async fn handle(self) -> anyhow::Result<()> {
        let data_directory =
            DataDirectory::load(self.data_directory.clone()).with_context(|| {
                format!("failed to load data directory at {}", self.data_directory.display())
            })?;

        Db::load(data_directory.database_path())
            .await
            .context("failed to apply store database migrations")?;

        Ok(())
    }
}
