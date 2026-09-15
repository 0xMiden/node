use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::ArgGroup;
use miden_node_store::allowlist::AccountAllowlist;
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{DataDirectory, Db, State};
use miden_node_tracing::info;
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::genesis::{OfficialNetwork, fetch_genesis_block, read_genesis_block};

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
        info!(
            target: crate::LOG_TARGET,
            "Node bootstrap complete",
            genesis.commitment = genesis_commitment,
            data.directory = self.data_directory.as_path()
        );
        Ok(())
    }
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
