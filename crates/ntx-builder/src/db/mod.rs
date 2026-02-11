use std::path::PathBuf;

use anyhow::Context;
use diesel::{Connection, SqliteConnection};
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::account::Account;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;
use tracing::{Instrument, info, instrument};

use crate::COMPONENT;
use crate::actor::inflight_note::InflightNetworkNote;
use crate::db::errors::{DatabaseError, DatabaseSetupError};
use crate::db::manager::{ConnectionManager, configure_connection_on_creation};
use crate::db::migrations::apply_migrations;
use crate::db::models::queries;

pub mod errors;
pub(crate) mod manager;
pub(crate) mod models;

mod migrations;
mod schema_hash;

/// [diesel](https://diesel.rs) generated schema.
pub(crate) mod schema;

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;

#[derive(Clone)]
pub struct Db {
    pool: deadpool_diesel::Pool<ConnectionManager, deadpool::managed::Object<ConnectionManager>>,
}

impl Db {
    /// Creates a new database file, configures it, and applies migrations.
    ///
    /// This is a synchronous one-shot setup used during node initialization.
    /// For runtime access with a connection pool, use [`Db::load`].
    #[instrument(
        target = COMPONENT,
        name = "ntx_builder.database.bootstrap",
        skip_all,
        fields(path=%database_filepath.display()),
        err,
    )]
    pub fn bootstrap(database_filepath: PathBuf) -> anyhow::Result<()> {
        let mut conn: SqliteConnection = diesel::sqlite::SqliteConnection::establish(
            database_filepath.to_str().context("database filepath is invalid")?,
        )
        .context("failed to open a database connection")?;

        configure_connection_on_creation(&mut conn)?;

        // Run migrations.
        apply_migrations(&mut conn).context("failed to apply database migrations")?;

        Ok(())
    }

    /// Create and commit a transaction with the queries added in the provided closure.
    pub(crate) async fn transact<R, E, Q, M>(&self, msg: M, query: Q) -> std::result::Result<R, E>
    where
        Q: Send
            + for<'a, 't> FnOnce(&'a mut SqliteConnection) -> std::result::Result<R, E>
            + 'static,
        R: Send + 'static,
        M: Send + ToString,
        E: From<diesel::result::Error>,
        E: From<DatabaseError>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let conn = self
            .pool
            .get()
            .in_current_span()
            .await
            .map_err(|e| DatabaseError::ConnectionPoolObtainError(Box::new(e)))?;

        conn.interact(|conn| <_ as diesel::Connection>::transaction::<R, E, Q>(conn, query))
            .in_current_span()
            .await
            .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }

    /// Run the query _without_ a transaction.
    pub(crate) async fn query<R, E, Q, M>(&self, msg: M, query: Q) -> std::result::Result<R, E>
    where
        Q: Send + FnOnce(&mut SqliteConnection) -> std::result::Result<R, E> + 'static,
        R: Send + 'static,
        M: Send + ToString,
        E: From<DatabaseError>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let conn = self
            .pool
            .get()
            .in_current_span()
            .await
            .map_err(|e| DatabaseError::ConnectionPoolObtainError(Box::new(e)))?;

        conn.interact(move |conn| {
            let r = query(conn)?;
            Ok(r)
        })
        .in_current_span()
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }

    /// Opens a connection pool to an existing database and re-applies pending migrations.
    ///
    /// Use [`Db::bootstrap`] first to create and initialize the database file.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(database_filepath: PathBuf) -> Result<Self, DatabaseSetupError> {
        let manager = ConnectionManager::new(database_filepath.to_str().unwrap());
        let pool = deadpool_diesel::Pool::builder(manager)
            .max_size(16)
            .build()
            .map_err(DatabaseSetupError::PoolBuild)?;

        info!(
            target: COMPONENT,
            sqlite = %database_filepath.display(),
            "Connected to the database"
        );

        let me = Db { pool };
        me.query("migrations", apply_migrations).await?;
        Ok(me)
    }

    // PUBLIC QUERY METHODS
    // ============================================================================================

    /// Returns `true` if there are notes available for consumption by the given account.
    pub async fn has_available_notes(
        &self,
        account_id: NetworkAccountId,
        block_num: BlockNumber,
        max_attempts: usize,
    ) -> Result<bool> {
        self.query("has_available_notes", move |conn| {
            let notes = queries::available_notes(conn, account_id, block_num, max_attempts)?;
            Ok(!notes.is_empty())
        })
        .await
    }

    /// Drops notes for the given account that have exceeded the maximum attempt count.
    pub async fn drop_failing_notes(
        &self,
        account_id: NetworkAccountId,
        max_attempts: usize,
    ) -> Result<()> {
        self.transact("drop_failing_notes", move |conn| {
            queries::drop_failing_notes(conn, account_id, max_attempts)
        })
        .await
    }

    /// Returns the latest account state and available notes for the given account.
    pub async fn select_candidate(
        &self,
        account_id: NetworkAccountId,
        block_num: BlockNumber,
        max_note_attempts: usize,
    ) -> Result<(Option<Account>, Vec<InflightNetworkNote>)> {
        self.query("select_candidate", move |conn| {
            let account = queries::latest_account(conn, account_id)?;
            let notes = queries::available_notes(conn, account_id, block_num, max_note_attempts)?;
            Ok((account, notes))
        })
        .await
    }

    /// Marks notes as failed by incrementing `attempt_count` and setting `last_attempt`.
    pub async fn notes_failed(
        &self,
        nullifiers: Vec<Nullifier>,
        block_num: BlockNumber,
    ) -> Result<()> {
        self.transact("notes_failed", move |conn| {
            queries::notes_failed(conn, &nullifiers, block_num)
        })
        .await
    }

    /// Handles a `TransactionAdded` mempool event by writing effects to the DB.
    pub async fn handle_transaction_added(
        &self,
        tx_id: TransactionId,
        account_delta: Option<AccountUpdateDetails>,
        notes: Vec<SingleTargetNetworkNote>,
        nullifiers: Vec<Nullifier>,
    ) -> Result<()> {
        self.transact("handle_transaction_added", move |conn| {
            queries::handle_transaction_added(
                conn,
                &tx_id,
                account_delta.as_ref(),
                &notes,
                &nullifiers,
            )
        })
        .await
    }

    /// Handles a `BlockCommitted` mempool event by committing transaction effects.
    pub async fn handle_block_committed(
        &self,
        txs: Vec<TransactionId>,
        block_num: BlockNumber,
        header: BlockHeader,
    ) -> Result<()> {
        self.transact("handle_block_committed", move |conn| {
            queries::handle_block_committed(conn, &txs, block_num, &header)
        })
        .await
    }

    /// Handles a `TransactionsReverted` mempool event by undoing transaction effects.
    ///
    /// Returns the list of account IDs whose creation was reverted.
    pub async fn handle_transactions_reverted(
        &self,
        tx_ids: Vec<TransactionId>,
    ) -> Result<Vec<NetworkAccountId>> {
        self.transact("handle_transactions_reverted", move |conn| {
            queries::handle_transactions_reverted(conn, &tx_ids)
        })
        .await
    }

    /// Purges all inflight state. Called on startup to get a clean slate.
    pub async fn purge_inflight(&self) -> Result<()> {
        self.transact("purge_inflight", queries::purge_inflight).await
    }

    /// Inserts or replaces the singleton chain state row.
    pub async fn upsert_chain_state(
        &self,
        block_num: BlockNumber,
        header: BlockHeader,
    ) -> Result<()> {
        self.transact("upsert_chain_state", move |conn| {
            queries::upsert_chain_state(conn, block_num, &header)
        })
        .await
    }

    /// Syncs an account and its notes from the store into the DB.
    pub async fn sync_account_from_store(
        &self,
        account_id: NetworkAccountId,
        account: Account,
        notes: Vec<SingleTargetNetworkNote>,
    ) -> Result<()> {
        self.transact("sync_account_from_store", move |conn| {
            queries::upsert_committed_account(conn, account_id, &account)?;
            queries::insert_committed_notes(conn, &notes)?;
            Ok(())
        })
        .await
    }

    /// Creates an in-memory SQLite connection for testing with migrations applied.
    ///
    /// This bypasses the async connection pool entirely, matching the store crate's test pattern.
    #[cfg(test)]
    pub fn test_conn() -> SqliteConnection {
        use crate::db::manager::configure_connection_on_creation;

        let mut conn =
            SqliteConnection::establish(":memory:").expect("in-memory sqlite should always work");
        configure_connection_on_creation(&mut conn).expect("connection configuration should work");
        apply_migrations(&mut conn).expect("migrations should apply on empty database");
        conn
    }
}
