mod account_state_forest;
mod accounts;
mod blocks;
mod data_directory;
mod db;
mod errors;
pub mod genesis;
mod proven_tip;
pub mod state;

#[cfg(feature = "rocksdb")]
pub use accounts::PersistentAccountTree;
pub use accounts::{AccountTreeWithHistory, HistoricalError, InMemoryAccountTree};
pub use data_directory::DataDirectory;
pub use db::models::conv::SqlTypeConvert;
pub use db::models::queries::StorageMapValuesPage;
pub use db::{
    AccountVaultValue,
    DatabaseOptions,
    Db,
    NoteRecord,
    NoteSyncRecord,
    NoteSyncUpdate,
    NullifierInfo,
    TransactionRecord,
};
pub use errors::{
    ApplyBlockError,
    ApplyBlockWithProvingInputsError,
    DatabaseError,
    GetAccountError,
    GetBatchInputsError,
    GetBlockHeaderError,
    GetBlockInputsError,
    NoteSyncError,
    StateSyncError,
};
pub use genesis::GenesisState;
pub use state::State;

/// Returns the store crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns the default number of SQLite connections used by store database pools.
pub fn default_sqlite_connection_pool_size() -> std::num::NonZeroUsize {
    DatabaseOptions::default().connection_pool_size
}

/// Test-only helpers exposed for downstream integration tests.
///
/// This module is hidden from public docs and not part of the stable API. It exists so
/// integration tests in sibling crates (e.g. `miden-node-rpc`) can seed network-account
/// rows directly into the store's SQLite database without us widening the visibility of
/// internal diesel types.
#[doc(hidden)]
pub mod test_support {
    use std::path::Path;

    use diesel::prelude::*;
    use miden_protocol::Word;
    use miden_protocol::account::AccountId;
    use miden_protocol::block::BlockNumber;

    use crate::db::models::queries::{AccountRowInsert, NetworkAccountType};
    use crate::db::schema;

    /// Opens a fresh connection to the store's SQLite database and inserts a private
    /// network-account row for `account_id`, marking it as a network account in the
    /// latest state at block 0.
    ///
    /// Intended for integration tests that need to exercise the network-account gate
    /// without running a transaction through the block producer. The store's WAL mode
    /// makes a secondary connection safe.
    pub fn seed_network_account(db_path: &Path, account_id: AccountId) {
        let mut conn = SqliteConnection::establish(db_path.to_str().expect("db path is utf-8"))
            .expect("connect to store sqlite");

        let row = AccountRowInsert::new_private(
            account_id,
            NetworkAccountType::Network,
            Word::default(),
            BlockNumber::from(0),
            BlockNumber::from(0),
        );
        diesel::insert_into(schema::accounts::table)
            .values(&row)
            .execute(&mut conn)
            .expect("insert network account row");
    }
}

// CONSTANTS
// =================================================================================================
const COMPONENT: &str = "miden-store";
