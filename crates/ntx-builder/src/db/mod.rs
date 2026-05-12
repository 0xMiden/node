use std::path::PathBuf;

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_standards::note::AccountTargetNetworkNote;
use tracing::{info, instrument};

use crate::db::migrations::apply_migrations;
use crate::db::models::queries;
use crate::inflight_note::InflightNetworkNote;
use crate::{COMPONENT, NoteError};

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

    /// Returns the latest execution error for a note identified by its note ID.
    pub async fn get_note_error(&self, note_id: NoteId) -> Result<Option<queries::NoteErrorRow>> {
        let note_id_bytes = models::conv::note_id_to_bytes(&note_id);
        self.inner
            .query("get_note_error", move |conn| queries::get_note_error(conn, &note_id_bytes))
            .await
    }

    /// Handles a `TransactionAdded` mempool event by writing effects to the DB.
    pub async fn handle_transaction_added(
        &self,
        tx_id: TransactionId,
        account_delta: Option<AccountUpdateDetails>,
        notes: Vec<AccountTargetNetworkNote>,
        nullifiers: Vec<Nullifier>,
    ) -> Result<()> {
        self.inner
            .transact("handle_transaction_added", move |conn| {
                queries::add_transaction(conn, &tx_id, account_delta.as_ref(), &notes, &nullifiers)
            })
            .await
    }

    /// Handles a `BlockCommitted` mempool event by committing transaction effects.
    ///
    /// Returns the list of affected account IDs that should be notified.
    ///
    /// `advance_next_block_to_sync` controls whether `next_block_to_sync` is advanced alongside
    /// the chain tip.
    ///
    /// During startup catch-up the caller passes `false`. If we advanced it here and then
    /// crashed mid-catch-up, the next restart would treat blocks we never actually pulled from
    /// the store as already synced and skip fetching their unconsumed-notes delta. Catch-up
    /// advances it explicitly once it completes successfully.
    ///
    /// In steady-state the caller passes `true`: the mempool stream is the source of truth for
    /// new blocks, so `next_block_to_sync` can follow the chain tip, storing `block_num + 1`.
    pub async fn handle_block_committed(
        &self,
        txs: Vec<TransactionId>,
        block_num: BlockNumber,
        header: BlockHeader,
        advance_next_block_to_sync: bool,
    ) -> Result<Vec<NetworkAccountId>> {
        self.inner
            .transact("handle_block_committed", move |conn| {
                let affected = queries::commit_block_effects(conn, &txs)?;
                queries::upsert_chain_state(conn, block_num, &header)?;
                if advance_next_block_to_sync {
                    queries::set_next_block_to_sync(conn, block_num.child())?;
                }
                Ok(affected)
            })
            .await
    }

    /// Handles a `TransactionsReverted` mempool event by undoing transaction effects.
    ///
    /// Returns all affected account IDs that should be notified.
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

    /// Returns the next chain block the ntx-builder should ingest from the store. Defaults to
    /// [`BlockNumber::GENESIS`] on first-ever startup.
    pub async fn read_next_block_to_sync(&self) -> Result<BlockNumber> {
        self.inner
            .query("read_next_block_to_sync", queries::read_next_block_to_sync)
            .await
    }

    /// Monotonically advances `next_block_to_sync`.
    pub async fn set_next_block_to_sync(&self, next_block_to_sync: BlockNumber) -> Result<()> {
        self.inner
            .transact("set_next_block_to_sync", move |conn| {
                queries::set_next_block_to_sync(conn, next_block_to_sync)
            })
            .await
    }

    /// Returns all account IDs with a committed row in the local DB.
    pub async fn list_committed_account_ids(&self) -> Result<Vec<NetworkAccountId>> {
        self.inner
            .query("list_committed_account_ids", queries::list_committed_account_ids)
            .await
    }

    /// Returns the distinct account IDs that have at least one inflight row at the time of the
    /// call. Intended for use *before* `purge_inflight` so the caller can reconcile those
    /// accounts' committed state from the store.
    pub async fn list_inflight_account_ids(&self) -> Result<Vec<NetworkAccountId>> {
        self.inner
            .query("list_inflight_account_ids", queries::list_inflight_account_ids)
            .await
    }

    /// Replaces committed note rows for the given set of notes. Account state is left untouched.
    ///
    /// Used by the per-account note refresh that runs at startup to catch up on notes that
    /// landed during the builder's downtime.
    pub async fn upsert_committed_notes(&self, notes: Vec<AccountTargetNetworkNote>) -> Result<()> {
        self.inner
            .transact("upsert_committed_notes", move |conn| {
                queries::insert_committed_notes(conn, &notes)
            })
            .await
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
        notes: Vec<AccountTargetNetworkNote>,
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

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    use super::*;
    use crate::test_utils::mock_block_header;

    /// `handle_block_committed` advances the chain tip but NOT `next_block_to_sync` when
    /// `advance_next_block_to_sync=false`.
    #[tokio::test]
    async fn handle_block_committed_does_not_advance_next_block_to_sync_when_gated() {
        let (db, _dir) = Db::test_setup().await;

        // Seed chain_state at block 0 so the row exists.
        let zero = BlockNumber::from(0u32);
        db.upsert_chain_state(zero, mock_block_header(zero)).await.unwrap();

        let block_num = BlockNumber::from(5u32);
        let header = mock_block_header(block_num);
        db.handle_block_committed(vec![], block_num, header, false).await.unwrap();

        let next_to_sync = db.read_next_block_to_sync().await.unwrap();
        assert_eq!(
            next_to_sync,
            BlockNumber::GENESIS,
            "next_block_to_sync must remain at GENESIS while catch-up is gated; got {next_to_sync}",
        );
    }

    /// `handle_block_committed` advances both the chain tip AND `next_block_to_sync` when
    /// `advance_next_block_to_sync=true`. This is the steady-state path: the mempool stream is
    /// delivering all the data we'd otherwise need from the store, so `next_block_to_sync` can
    /// follow the chain tip (set to `block_num + 1` which is the next block to sync).
    #[tokio::test]
    async fn handle_block_committed_advances_next_block_to_sync_when_caught_up() {
        let (db, _dir) = Db::test_setup().await;

        let zero = BlockNumber::from(0u32);
        db.upsert_chain_state(zero, mock_block_header(zero)).await.unwrap();

        let block_num = BlockNumber::from(5u32);
        let header = mock_block_header(block_num);
        db.handle_block_committed(vec![], block_num, header, true).await.unwrap();

        let next_to_sync = db.read_next_block_to_sync().await.unwrap();
        assert_eq!(next_to_sync, block_num.child());
    }

    /// Going from gated → caught-up → gated again, `next_block_to_sync` should advance only when
    /// the flag is true and never regress when it's false.
    #[tokio::test]
    async fn handle_block_committed_next_block_to_sync_is_monotone_across_modes() {
        let (db, _dir) = Db::test_setup().await;

        let zero = BlockNumber::from(0u32);
        db.upsert_chain_state(zero, mock_block_header(zero)).await.unwrap();

        // Gated: chain tip moves to 5, next_block_to_sync stays at GENESIS.
        db.handle_block_committed(vec![], BlockNumber::from(5u32), mock_block_header(zero), false)
            .await
            .unwrap();
        assert_eq!(db.read_next_block_to_sync().await.unwrap(), BlockNumber::GENESIS);

        // Caught up: next_block_to_sync advances to 8 (= 7.child()).
        db.handle_block_committed(vec![], BlockNumber::from(7u32), mock_block_header(zero), true)
            .await
            .unwrap();
        assert_eq!(db.read_next_block_to_sync().await.unwrap(), BlockNumber::from(7u32).child(),);

        // Gated again (shouldn't normally happen, but the guard must hold): stays at 8.
        db.handle_block_committed(vec![], BlockNumber::from(9u32), mock_block_header(zero), false)
            .await
            .unwrap();
        assert_eq!(db.read_next_block_to_sync().await.unwrap(), BlockNumber::from(7u32).child(),);

        // Caught up at higher block.
        db.handle_block_committed(vec![], BlockNumber::from(10u32), mock_block_header(zero), true)
            .await
            .unwrap();
        assert_eq!(db.read_next_block_to_sync().await.unwrap(), BlockNumber::from(10u32).child(),);
    }
}
