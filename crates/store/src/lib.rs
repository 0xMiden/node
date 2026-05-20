mod account_state_forest;
mod accounts;
mod blocks;
mod db;
mod errors;
pub mod genesis;
mod proven_tip;
mod server;
pub mod state;

#[cfg(feature = "rocksdb")]
pub use accounts::PersistentAccountTree;
pub use accounts::{AccountTreeWithHistory, HistoricalError, InMemoryAccountTree};
pub use db::Db;
pub use db::models::conv::SqlTypeConvert;
pub use errors::{ApplyBlockError, DatabaseError, StateInitializationError};
pub use genesis::GenesisState;
pub use proven_tip::ProvenTipWriter;
pub use server::block_prover_client::BlockProver;
pub use server::proof_scheduler::DEFAULT_MAX_CONCURRENT_PROOFS;
pub use server::{DataDirectory, DatabaseOptions, Store, StoreApi, StoreMode};
pub use server::serve_ntx_builder_and_replica;
pub use state::{Finality, State};

/// Returns the default number of SQLite connections used by store database pools.
pub fn default_sqlite_connection_pool_size() -> std::num::NonZeroUsize {
    DatabaseOptions::default().connection_pool_size
}

// CONSTANTS
// =================================================================================================
const COMPONENT: &str = "miden-store";
