use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::Word;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::note::{NoteId, NoteScript, Nullifier};
use miden_standards::note::AccountTargetNetworkNote;
use tracing::{info, instrument};

use crate::committed_block::CommittedBlockEffects;
use crate::db::migrations::apply_migrations;
use crate::db::models::queries;
use crate::{COMPONENT, NoteError};

pub(crate) mod models;

mod migrations;

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
        Self::setup_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size())
            .await
    }

    /// Creates and initializes the database with a specific pool size.
    #[instrument(
        target = COMPONENT,
        name = "ntx_builder.database.setup",
        skip_all,
        fields(path=%database_filepath.display()),
        err,
    )]
    pub async fn setup_with_pool_size(
        database_filepath: PathBuf,
        connection_pool_size: NonZeroUsize,
    ) -> anyhow::Result<Self> {
        apply_migrations(&database_filepath).context("failed to apply migrations")?;

        let inner = miden_node_db::Db::new_with_pool_size(&database_filepath, connection_pool_size)
            .context("failed to build connection pool")?;

        info!(
            target: COMPONENT,
            sqlite = %database_filepath.display(),
            connection_pool_size = %connection_pool_size,
            "Connected to the database"
        );

        Ok(Db { inner })
    }

    // BLOCK APPLICATION
    // ============================================================================================

    /// Applies the effects of a committed block (account upserts, note inserts, nullifier-driven
    /// deletes, and chain-state advancement) in a single transaction. Returns the set of network
    /// accounts touched by this block.
    pub async fn apply_committed_block(
        &self,
        effects: CommittedBlockEffects,
        chain_mmr: PartialMmr,
    ) -> Result<Vec<NetworkAccountId>> {
        self.inner
            .transact("apply_committed_block", move |conn| {
                queries::apply_committed_block(conn, &effects, &chain_mmr)
            })
            .await
    }

    /// Reads the singleton chain state row, returning the last synced block number, its header, and
    /// the persisted chain MMR if any block has been applied locally.
    pub async fn get_chain_state(&self) -> Result<Option<(BlockNumber, BlockHeader, PartialMmr)>> {
        self.inner.query("get_chain_state", queries::select_chain_state).await
    }

    // ACTOR-PATH QUERIES
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

    /// Returns `true` if a committed account state exists for the given account.
    pub async fn has_committed_account(&self, account_id: NetworkAccountId) -> Result<bool> {
        self.inner
            .query("has_committed_account", move |conn| {
                Ok(queries::get_account(conn, account_id)?.is_some())
            })
            .await
    }

    /// Returns the latest account state and available notes for the given account.
    pub async fn select_candidate(
        &self,
        account_id: NetworkAccountId,
        block_num: BlockNumber,
        max_note_attempts: usize,
    ) -> Result<(Option<miden_protocol::account::Account>, Vec<AccountTargetNetworkNote>)> {
        self.inner
            .query("select_candidate", move |conn| {
                let account = queries::get_account(conn, account_id)?;
                let notes =
                    queries::available_notes(conn, account_id, block_num, max_note_attempts)?;
                Ok((account, notes))
            })
            .await
    }

    /// Returns the distinct set of network accounts that currently have at least one pending
    /// (unconsumed, within attempt budget) note.
    pub async fn accounts_with_pending_notes(
        &self,
        max_attempts: usize,
    ) -> Result<Vec<NetworkAccountId>> {
        self.inner
            .query("accounts_with_pending_notes", move |conn| {
                queries::accounts_with_pending_notes(conn, max_attempts)
            })
            .await
    }

    /// Marks notes as failed by incrementing `attempt_count`, setting `last_attempt`, and storing
    /// the latest error message.
    pub async fn notes_failed(
        &self,
        failed_notes: Vec<(Nullifier, NoteError)>,
        block_num: BlockNumber,
    ) -> Result<()> {
        self.inner
            .transact("notes_failed", move |conn| {
                queries::notes_failed(conn, &failed_notes, block_num)
            })
            .await
    }

    /// Returns the status for a note identified by its note ID.
    pub async fn get_note_status(&self, note_id: NoteId) -> Result<Option<queries::NoteStatusRow>> {
        let note_id_bytes = models::conv::note_id_to_bytes(&note_id);
        self.inner
            .query("get_note_status", move |conn| queries::get_note_status(conn, &note_id_bytes))
            .await
    }

    // SCRIPT CACHE
    // ============================================================================================

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
        apply_migrations(&db_path).expect("migrations should apply on empty database");
        let mut conn = SqliteConnection::establish(db_path.to_str().unwrap())
            .expect("temp file sqlite should always work");
        configure_connection_on_creation(&mut conn).expect("connection configuration should work");
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
