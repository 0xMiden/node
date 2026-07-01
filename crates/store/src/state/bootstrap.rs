use std::path::Path;

use anyhow::Context;
use miden_node_utils::tracing::miden_instrument;

use crate::blocks::BlockStore;
use crate::db::Db;
use crate::genesis::GenesisBlock;
use crate::state::State;
use crate::{COMPONENT, DataDirectory, LOG_TARGET};

impl State {
    /// Bootstraps the store state, creating the database state and inserting the genesis block
    /// data.
    #[miden_instrument(
        target = COMPONENT,
        name = "store.bootstrap",
        skip_all,
        err,
    )]
    pub fn bootstrap(genesis: GenesisBlock, data_directory: &Path) -> anyhow::Result<()> {
        let data_directory =
            DataDirectory::load(data_directory.to_path_buf()).with_context(|| {
                format!("failed to load data directory at {}", data_directory.display())
            })?;
        tracing::info!(target: LOG_TARGET, path=%data_directory.display(), "Data directory loaded");

        let block_store_path = data_directory.block_store_dir();
        let block_store =
            BlockStore::bootstrap(block_store_path.clone(), &genesis).with_context(|| {
                format!("failed to bootstrap block store at {}", block_store_path.display())
            })?;
        tracing::info!(target: LOG_TARGET, path=%block_store.display(), "Block store created");

        let database_filepath = data_directory.database_path();
        Db::bootstrap(database_filepath.clone(), genesis).with_context(|| {
            format!("failed to bootstrap database at {}", database_filepath.display())
        })?;
        tracing::info!(target: LOG_TARGET, path=%database_filepath.display(), "Database created");

        Ok(())
    }
}
