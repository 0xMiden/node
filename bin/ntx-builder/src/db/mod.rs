use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::note::{NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_standards::note::AccountTargetNetworkNote;
use tracing::info;

use crate::committed_block::CommittedBlockEffects;
use crate::db::migrations::{bootstrap_database, migrate_database, verify_latest_schema};
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
    /// Opens an async connection pool after verifying the database is at the latest schema version.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "ntx_builder.database.load",
        skip_all,
        fields(path=%database_filepath.display()),
        err,
    )]
    pub async fn load(database_filepath: PathBuf) -> anyhow::Result<Self> {
        Self::load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size())
            .await
    }

    /// Opens an async connection pool with a specific pool size after verifying the database is at
    /// the latest schema version.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "ntx_builder.database.load",
        skip_all,
        fields(path=%database_filepath.display()),
        err,
    )]
    pub async fn load_with_pool_size(
        database_filepath: PathBuf,
        connection_pool_size: NonZeroUsize,
    ) -> anyhow::Result<Self> {
        verify_latest_schema(&database_filepath).context("failed to verify database schema")?;

        Self::open_with_pool_size(&database_filepath, connection_pool_size)
    }

    /// Applies all pending migrations to an existing DB.
    #[miden_node_utils::tracing::miden_instrument(target = COMPONENT, skip_all)]
    pub fn migrate(database_filepath: impl AsRef<Path>) -> Result<()> {
        migrate_database(database_filepath.as_ref())?;
        Ok(())
    }

    fn open_with_pool_size(
        database_filepath: &Path,
        connection_pool_size: NonZeroUsize,
    ) -> anyhow::Result<Self> {
        let inner = miden_node_db::Db::new_with_pool_size(database_filepath, connection_pool_size)
            .context("failed to build connection pool")?;

        info!(
            target: COMPONENT,
            sqlite = %database_filepath.display(),
            connection_pool_size = %connection_pool_size,
            "Connected to the database"
        );

        Ok(Db { inner })
    }

    /// Creates and initializes the database, then seeds it with the signed genesis block.
    ///
    /// Mirrors the store's bootstrap (`Db::bootstrap`): after this completes the singleton
    /// `chain_state` row exists at [`BlockNumber::GENESIS`], so [`crate::NtxBuilderConfig::build`]
    /// can assume the genesis block is always present and never has to consume it from the
    /// committed-block subscription on startup.
    ///
    /// Returns an error if the database has already been bootstrapped.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "ntx_builder.database.bootstrap",
        skip_all,
        fields(path=%database_filepath.display()),
        err,
    )]
    pub async fn bootstrap(
        database_filepath: PathBuf,
        genesis: &SignedBlock,
    ) -> anyhow::Result<()> {
        bootstrap_database(&database_filepath).context("failed to bootstrap database schema")?;
        let db = Self::open_with_pool_size(
            &database_filepath,
            miden_node_db::default_connection_pool_size(),
        )?;

        let genesis_commitment = genesis.header().commitment();
        let genesis_header = genesis.header().clone();

        db.inner
            .transact("insert_genesis_chain_state", move |conn| {
                queries::insert_genesis_chain_state(conn, &genesis_header, &genesis_commitment)
            })
            .await
            .context("failed to seed genesis chain state")?;

        let effects = CommittedBlockEffects::from_signed_block(genesis);
        db.apply_committed_block(effects, PartialMmr::default())
            .await
            .context("failed to insert genesis block")?;

        Ok(())
    }

    /// Reads the genesis block commitment persisted at bootstrap.
    pub async fn get_genesis_commitment(&self) -> Result<Word> {
        self.inner
            .query("get_genesis_commitment", queries::select_genesis_commitment)
            .await
    }

    // BLOCK APPLICATION
    // ============================================================================================

    /// Applies the effects of a committed block (account upserts, note inserts, nullifier-driven
    /// deletes, and chain-state advancement) in a single transaction.
    pub async fn apply_committed_block(
        &self,
        effects: CommittedBlockEffects,
        chain_mmr: PartialMmr,
    ) -> Result<()> {
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
        account_id: AccountId,
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

    /// Returns `true` if a committed state for the given account is tracked locally.
    ///
    /// The coordinator uses this to defer actor spawning until the account's creation transaction
    /// has been committed.
    pub async fn account_exists(&self, account_id: AccountId) -> Result<bool> {
        self.inner
            .query("account_exists", move |conn| queries::account_exists(conn, account_id))
            .await
    }

    /// Returns the committed account state for the given network account, if one is tracked locally.
    ///
    /// Actors load their account once at startup with this and keep it in memory afterwards,
    /// advancing it from the committed state the coordinator pushes after each block.
    pub async fn get_account(
        &self,
        account_id: AccountId,
    ) -> Result<Option<miden_protocol::account::Account>> {
        self.inner
            .query("get_account", move |conn| queries::get_account(conn, account_id))
            .await
    }

    /// Returns the notes currently available for consumption by the given account.
    pub async fn available_notes(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        max_note_attempts: usize,
    ) -> Result<Vec<AccountTargetNetworkNote>> {
        self.inner
            .query("available_notes", move |conn| {
                queries::available_notes(conn, account_id, block_num, max_note_attempts)
            })
            .await
    }

    /// Returns the distinct set of network accounts that currently have at least one pending
    /// (unconsumed, within attempt budget) note.
    pub async fn accounts_with_pending_notes(&self, max_attempts: usize) -> Result<Vec<AccountId>> {
        self.inner
            .query("accounts_with_pending_notes", move |conn| {
                queries::accounts_with_pending_notes(conn, max_attempts)
            })
            .await
    }

    /// Returns the latest transaction recorded against `account_id` in a committed block, if any.
    /// An actor waiting on its submission compares this against its own transaction id to confirm
    /// landing.
    pub async fn account_last_tx(&self, account_id: AccountId) -> Result<Option<TransactionId>> {
        self.inner
            .query("account_last_tx", move |conn| queries::account_last_tx(conn, account_id))
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

    /// Pins a dedicated connection for the builder's event loop, returning a [`LoopDb`].
    ///
    /// The loop performs its writes through the pinned connection so it never competes with the
    /// account actors for the shared pool.
    pub async fn pin_loop_connection(&self) -> Result<LoopDb> {
        Ok(LoopDb {
            conn: self.inner.pinned_connection().await?,
        })
    }

    /// Creates a file-backed SQLite test connection with migrations applied.
    #[cfg(test)]
    pub fn test_conn() -> (diesel::SqliteConnection, tempfile::TempDir) {
        use diesel::{Connection, SqliteConnection};
        use miden_node_db::configure_connection_on_creation;

        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("test.sqlite3");
        bootstrap_database(&db_path).expect("database should bootstrap");
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
        bootstrap_database(&db_path).expect("database should bootstrap");
        let db = Db::load(db_path).await.expect("test DB load should succeed");
        (db, dir)
    }

    /// Seeds a committed account row (and its `last_tx_id`) for tests that exercise the actor's
    /// landing detection without driving a full committed block.
    #[cfg(test)]
    pub async fn upsert_account_for_test(
        &self,
        account_id: AccountId,
        account: miden_protocol::account::Account,
        last_tx_id: TransactionId,
    ) -> Result<()> {
        self.inner
            .transact("test_upsert_account", move |conn| {
                queries::upsert_account(conn, account_id, &account, last_tx_id)
            })
            .await
    }
}

/// The subset of write operations the builder's event loop performs, bound to a connection pinned
/// out of [`Db`]'s pool. Routing the loop's writes here keeps block application off the shared pool
/// that the account actors hammer, so the loop is never starved of a connection.
pub struct LoopDb {
    conn: miden_node_db::PinnedConnection,
}

impl LoopDb {
    /// Applies a committed block's effects (see [`Db::apply_committed_block`]) on the pinned
    /// connection.
    pub async fn apply_committed_block(
        &self,
        effects: CommittedBlockEffects,
        chain_mmr: PartialMmr,
    ) -> Result<()> {
        self.conn
            .transact("apply_committed_block", move |conn| {
                queries::apply_committed_block(conn, &effects, &chain_mmr)
            })
            .await
    }

    /// Returns the network accounts with carry-over pending notes (see
    /// [`Db::accounts_with_pending_notes`]) on the pinned connection.
    pub async fn accounts_with_pending_notes(&self, max_attempts: usize) -> Result<Vec<AccountId>> {
        self.conn
            .query("accounts_with_pending_notes", move |conn| {
                queries::accounts_with_pending_notes(conn, max_attempts)
            })
            .await
    }

    /// Marks notes as failed (see [`Db::notes_failed`]) on the pinned connection.
    pub async fn notes_failed(
        &self,
        failed_notes: Vec<(Nullifier, NoteError)>,
        block_num: BlockNumber,
    ) -> Result<()> {
        self.conn
            .transact("notes_failed", move |conn| {
                queries::notes_failed(conn, &failed_notes, block_num)
            })
            .await
    }

    /// Persists a note script to the local cache (see [`Db::insert_note_script`]) on the pinned
    /// connection.
    pub async fn insert_note_script(&self, script_root: Word, script: &NoteScript) -> Result<()> {
        let script = script.clone();
        self.conn
            .transact("insert_note_script", move |conn| {
                queries::insert_note_script(conn, &script_root, &script)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{mock_genesis_block, mock_genesis_block_with_network_account};

    #[tokio::test]
    async fn bootstrap_seeds_genesis_network_account() {
        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("ntx-builder.sqlite3");

        let (genesis, account_id) = mock_genesis_block_with_network_account();
        Db::bootstrap(db_path.clone(), &genesis)
            .await
            .expect("bootstrap should succeed with a network account in genesis");

        let db = Db::load(db_path).await.expect("load should open the bootstrapped database");
        assert!(
            db.get_account(account_id).await.expect("query should succeed").is_some(),
            "genesis network account should be committed after bootstrap",
        );
    }

    #[tokio::test]
    async fn bootstrap_seeds_genesis_chain_state() {
        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("ntx-builder.sqlite3");

        Db::bootstrap(db_path.clone(), &mock_genesis_block())
            .await
            .expect("bootstrap should succeed on a fresh database");

        let db = Db::load(db_path).await.expect("load should open the bootstrapped database");
        let (block_num, ..) = db
            .get_chain_state()
            .await
            .expect("query should succeed")
            .expect("chain state should be present after bootstrap");

        assert_eq!(block_num, BlockNumber::GENESIS);
    }

    #[tokio::test]
    async fn bootstrap_rejects_already_bootstrapped_database() {
        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("ntx-builder.sqlite3");

        Db::bootstrap(db_path.clone(), &mock_genesis_block())
            .await
            .expect("first bootstrap should succeed");

        let err = Db::bootstrap(db_path, &mock_genesis_block())
            .await
            .expect_err("second bootstrap should fail");
        assert!(
            err.chain().any(|source| source.to_string().contains("database already exists")),
            "unexpected error: {err}"
        );
    }
}
