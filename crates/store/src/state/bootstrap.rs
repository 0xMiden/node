use std::path::Path;

use anyhow::Context;
use miden_node_tracing::{debug, miden_instrument};

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
        err,
    )]
    pub async fn bootstrap(genesis: GenesisBlock, data_directory: &Path) -> anyhow::Result<()> {
        let data_directory =
            DataDirectory::load(data_directory.to_path_buf()).with_context(|| {
                format!("failed to load data directory at {}", data_directory.display())
            })?;
        debug!(
            target: LOG_TARGET,
            "Data directory loaded",
            path = data_directory
        );

        let block_store_path = data_directory.block_store_dir();
        let _block_store =
            BlockStore::bootstrap(block_store_path.clone(), &genesis).with_context(|| {
                format!("failed to bootstrap block store at {}", block_store_path.display())
            })?;
        debug!(
            target: LOG_TARGET,
            "Block store created",
            path = block_store_path
        );

        let database_filepath = data_directory.database_path();
        Db::bootstrap(database_filepath.clone(), genesis).await.with_context(|| {
            format!("failed to bootstrap database at {}", database_filepath.display())
        })?;
        debug!(
            target: LOG_TARGET,
            "Database created",
            path = database_filepath
        );

        Ok(())
    }
}
