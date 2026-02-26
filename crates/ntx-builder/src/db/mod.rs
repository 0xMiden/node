use std::path::PathBuf;

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::db::migrations::apply_migrations;
use crate::db::models::queries;
use crate::inflight_note::InflightNetworkNote;

pub(crate) mod models;

mod migrations;
mod schema_hash;

/// [diesel](https://diesel.rs) generated schema.
pub(crate) mod schema;

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;

#[derive(Clone)]
pub struct Db {
    inner: miden_node_db::Db,
}

impl Db {
    /// Creates and initializes the database, then opens an async connection pool.
    #[instrument(
        target = COMPONENT,
        name = "ntx_builder.database.setup",
        skip_all,
        fields(path=%database_filepath.display()),
        err,
    )]
    pub async fn setup(database_filepath: PathBuf) -> anyhow::Result<Self> {
        let inner = miden_node_db::Db::new(&database_filepath)
            .context("failed to build connection pool")?;

        info!(
            target: COMPONENT,
            sqlite = %database_filepath.display(),
            "Connected to the database"
        );

        let me = Db { inner };
        me.inner
            .query("migrations", apply_migrations)
            .await
            .context("failed to apply migrations on pool connection")?;
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
        self.inner
            .query("has_available_notes", move |conn| {
                let notes = queries::available_notes(conn, account_id, block_num, max_attempts)?;
                Ok(!notes.is_empty())
            })
            .await
    }

    /// Returns `true` when an inflight account row exists with the given transaction ID.
    pub async fn transaction_exists(&self, tx_id: TransactionId) -> Result<bool> {
        self.inner
            .query("transaction_exists", move |conn| queries::transaction_exists(conn, &tx_id))
            .await
    }

    /// Returns the latest account state and available notes for the given account.
    pub async fn select_candidate(
        &self,
        account_id: NetworkAccountId,
        block_num: BlockNumber,
        max_note_attempts: usize,
    ) -> Result<(Option<Account>, Vec<InflightNetworkNote>)> {
        self.inner
            .query("select_candidate", move |conn| {
                let account = queries::get_account(conn, account_id)?;
                let notes =
                    queries::available_notes(conn, account_id, block_num, max_note_attempts)?;
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
        self.inner
            .transact("notes_failed", move |conn| {
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
        self.inner
            .transact("handle_transaction_added", move |conn| {
                queries::add_transaction(conn, &tx_id, account_delta.as_ref(), &notes, &nullifiers)
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
        self.inner
            .transact("handle_block_committed", move |conn| {
                queries::commit_block(conn, &txs, block_num, &header)
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
        self.inner
            .transact("handle_transactions_reverted", move |conn| {
                queries::revert_transaction(conn, &tx_ids)
            })
            .await
    }

    /// Purges all inflight state. Called on startup to get a clean slate.
    pub async fn purge_inflight(&self) -> Result<()> {
        self.inner.transact("purge_inflight", queries::purge_inflight).await
    }

    /// Inserts or replaces the singleton chain state row.
    pub async fn upsert_chain_state(
        &self,
        block_num: BlockNumber,
        header: BlockHeader,
    ) -> Result<()> {
        self.inner
            .transact("upsert_chain_state", move |conn| {
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
        self.inner
            .transact("sync_account_from_store", move |conn| {
                queries::upsert_committed_account(conn, account_id, &account)?;
                queries::insert_committed_notes(conn, &notes)?;
                Ok(())
            })
            .await
    }

    /// Looks up a cached note script by root hash.
    pub async fn lookup_note_script(&self, script_root: Word) -> Result<Option<NoteScript>> {
        self.inner
            .query("lookup_note_script", move |conn| {
                queries::lookup_note_script(conn, &script_root)
            })
            .await
    }

    /// Persists a note script to the local cache.
    pub async fn insert_note_script(&self, script_root: Word, script: &NoteScript) -> Result<()> {
        let script = script.clone();
        self.inner
            .transact("insert_note_script", move |conn| {
                queries::insert_note_script(conn, &script_root, &script)
            })
            .await
    }

    /// Creates a file-backed SQLite test connection with migrations applied.
    #[cfg(test)]
    pub fn test_conn() -> (diesel::SqliteConnection, tempfile::TempDir) {
        use diesel::{Connection, SqliteConnection};
        use miden_node_db::configure_connection_on_creation;

        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("test.sqlite3");
        let mut conn = SqliteConnection::establish(db_path.to_str().unwrap())
            .expect("temp file sqlite should always work");
        configure_connection_on_creation(&mut conn).expect("connection configuration should work");
        apply_migrations(&mut conn).expect("migrations should apply on empty database");
        (conn, dir)
    }

    /// Creates an async `Db` instance backed by a temp file for testing.
    ///
    /// Returns `(Db, TempDir)` — the `TempDir` must be kept alive for the DB's lifetime.
    #[cfg(test)]
    pub async fn test_setup() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("test.sqlite3");
        let db = Db::setup(db_path).await.expect("test DB setup should succeed");
        (db, dir)
    }
}
