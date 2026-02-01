mod accounts;
mod blocks;
mod db;
mod errors;
pub mod genesis;
mod inner_forest;
mod server;
pub mod state;

#[cfg(feature = "rocksdb")]
pub use accounts::PersistentAccountTree;
pub use accounts::{AccountTreeWithHistory, HistoricalError, InMemoryAccountTree};
pub use genesis::GenesisState;
pub use server::block_prover_client::BlockProver;
pub use server::{DataDirectory, Store};

// CONSTANTS
// =================================================================================================
const COMPONENT: &str = "miden-store";
