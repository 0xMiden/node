use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{DataDirectory, Db, Store};
use miden_node_utils::fs::ensure_empty_directory;
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;

use super::ENV_DATA_DIRECTORY;

// BOOTSTRAP
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct BootstrapCommand {
    /// Directory to initialize with the node's local data storage.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    /// Path to the trusted, signed genesis block file.
    #[arg(long, value_name = "FILE")]
    genesis_block: PathBuf,
}

impl BootstrapCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        ensure_empty_directory(&self.data_directory)?;
        bootstrap_store(&self.data_directory, &self.genesis_block)
    }
}

/// Reads a genesis block from disk, validates it, and bootstraps the store.
pub fn bootstrap_store(data_directory: &Path, genesis_block_path: &Path) -> anyhow::Result<()> {
    let bytes = fs_err::read(genesis_block_path).context("failed to read genesis block")?;
    let signed_block = SignedBlock::read_from_bytes(&bytes)
        .context("failed to deserialize genesis block from file")?;
    let genesis_block =
        GenesisBlock::try_from(signed_block).context("genesis block validation failed")?;

    Store::bootstrap(genesis_block, data_directory)
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
