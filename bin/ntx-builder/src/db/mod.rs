use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_node_tracing::{info, miden_instrument};
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock, ValidatorConfig};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::note::{Note, NoteId, NoteScript, Nullifier};
#[cfg(test)]
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{ByteReader, ByteWriter, Deserializable, Serializable};
#[cfg(test)]
use miden_standards::note::AccountTargetNetworkNote;

use crate::committed_block::CommittedBlockEffects;
use crate::db::migrations::{bootstrap_database, migrate_database, verify_latest_schema};
use crate::db::queries::NoteStatusRow;
#[cfg(test)]
use crate::sponsorship::SponsorshipNote;
use crate::{COMPONENT, NoteError, db};

pub(crate) mod queries;

mod migrations;

/// Reason recorded in a note's `last_error` when it is discarded for exceeding the per-tx cycle
/// budget on its own.
pub(crate) const OVERSIZED_NOTE_DISCARD_REASON: &str =
    "note consumption exceeds the per-transaction cycle budget; it can never be consumed";

/// Genesis validator keys persisted in the pre-0.17 native encoding.
///
/// The transaction-encryption trust root only needs the ordered keys, not the quorum newly carried
/// by [`ValidatorConfig`]. Keeping this wrapper encoded as `Vec<PublicKey>` preserves the existing
/// database representation while the runtime block header uses `ValidatorConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisValidatorKeys(Vec<ValidatorPublicKey>);

impl GenesisValidatorKeys {
    fn from_validator_config(config: &ValidatorConfig) -> Self {
        Self(config.keys().to_vec())
    }

    pub(crate) fn keys(&self) -> &[ValidatorPublicKey] {
        &self.0
    }
}

impl Serializable for GenesisValidatorKeys {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for GenesisValidatorKeys {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_protocol::utils::serde::DeserializationError> {
        let keys = Vec::<ValidatorPublicKey>::read_from(source)?;
        let quorum = u16::try_from(keys.len()).map_err(|_| {
            miden_protocol::utils::serde::DeserializationError::InvalidValue(
                "validator key count does not fit in u16".into(),
            )
        })?;
        ValidatorConfig::new(keys.clone(), quorum).map_err(|err| {
            miden_protocol::utils::serde::DeserializationError::InvalidValue(err.to_string())
        })?;
        Ok(Self(keys))
    }
}

miden_node_db::impl_blob_codec!(GenesisValidatorKeys);

// NTX BUILDER DATABASE
// ================================================================================================

/// Read-only handle to the ntx-builder database.
///
/// Wraps the framework [`DbReader`] and exposes every read query as a method. Cloneable, and handed
/// to read-only components (the gRPC server, the coordinator, and actors); it has no write methods,
/// so those components cannot mutate the database.
#[derive(Clone)]
pub(crate) struct NtxDbReader {
    reader: DbReader,
}

impl NtxDbReader {
    pub(crate) async fn select_genesis_commitment(&self) -> Result<Option<Word>, DatabaseError> {
        self.reader
            .read("select_genesis_commitment", db::queries::select_genesis_commitment)
            .await
    }

    /// Reads the validator signing keys persisted from the genesis header.
    pub(crate) async fn select_genesis_validator_keys(
        &self,
    ) -> Result<Option<GenesisValidatorKeys>, DatabaseError> {
        self.reader
            .read("select_genesis_validator_keys", db::queries::select_genesis_validator_keys)
            .await
    }

    pub(crate) async fn get_account(
        &self,
        account_id: AccountId,
    ) -> Result<Option<Account>, DatabaseError> {
        self.reader
            .read("get_account", move |tx| queries::get_account(tx, account_id))
            .await
    }

    /// Returns `true` if the account has any pending (unconsumed, within attempt budget) note. Used
    /// by the coordinator to decide whether to respawn an actor that just idle-timed-out, without
    /// loading or deserializing the notes themselves.
    pub(crate) async fn account_has_pending_notes(
        &self,
        account_id: AccountId,
        max_attempts: usize,
    ) -> Result<bool, DatabaseError> {
        self.reader
            .read("account_has_pending_notes", move |tx| {
                queries::account_has_pending_notes(tx, account_id, max_attempts)
            })
            .await
    }

    /// Returns the notes currently available for consumption by the given account, along with the
    /// earliest block at which a currently-ineligible note becomes eligible (see
    /// [`queries::AvailableNotes`]).
    pub(crate) async fn available_notes(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        max_note_attempts: usize,
    ) -> Result<queries::AvailableNotes, DatabaseError> {
        self.reader
            .read("available_notes", move |tx| {
                queries::available_notes(tx, account_id, block_num, max_note_attempts)
            })
            .await
    }

    pub(crate) async fn select_chain_state(
        &self,
    ) -> Result<Option<(BlockNumber, BlockHeader, PartialMmr)>, DatabaseError> {
        self.reader.read("select_chain_state", queries::select_chain_state).await
    }

    pub(crate) async fn account_exists(
        &self,
        account_id: AccountId,
    ) -> Result<bool, DatabaseError> {
        self.reader
            .read("account_exists", move |tx| db::queries::account_exists(tx, account_id))
            .await
    }

    pub(crate) async fn accounts_with_pending_notes(
        &self,
        max_note_attempts: usize,
    ) -> Result<Vec<AccountId>, DatabaseError> {
        self.reader
            .read("accounts_with_pending_notes", move |tx| {
                queries::accounts_with_pending_notes(tx, max_note_attempts)
            })
            .await
    }

    /// The committed-transaction landing check reads `last_committed_tx` from the `AccountView` the
    /// coordinator pushes, so this read accessor is only used by tests to verify that
    /// `upsert_account` persists `accounts.last_tx_id` correctly.
    #[cfg(test)]
    pub(crate) async fn account_last_tx(
        &self,
        account_id: AccountId,
    ) -> Result<Option<TransactionId>, DatabaseError> {
        self.reader
            .read("account_last_tx", move |tx| queries::account_last_tx(tx, account_id))
            .await
    }

    pub(crate) async fn lookup_note_script(
        &self,
        script_root: Word,
    ) -> Result<Option<NoteScript>, DatabaseError> {
        self.reader
            .read("lookup_note_script", move |tx| queries::lookup_note_script(tx, &script_root))
            .await
    }

    pub(crate) async fn get_note_status(
        &self,
        note_id: NoteId,
    ) -> Result<Option<NoteStatusRow>, DatabaseError> {
        self.reader
            .read("get_note_status", move |tx| crate::db::queries::get_note_status(tx, note_id))
            .await
    }

    /// Returns the unconsumed `FEE_SPONSORSHIP` notes bound to the account's unconsumed feature
    /// notes, grouped by feature note id. Used by transaction selection to attach each feature
    /// note's sponsorships to its group.
    pub(crate) async fn sponsorships_for_pending_notes(
        &self,
        account_id: AccountId,
    ) -> Result<HashMap<NoteId, Vec<Note>>, DatabaseError> {
        self.reader
            .read("sponsorships_for_pending_notes", move |tx| {
                queries::select_sponsorships_for_pending_notes(tx, account_id)
            })
            .await
    }
}

/// Write handle to the ntx-builder database.
///
/// Wraps the framework [`DbWriter`] and additionally holds an [`NtxDbReader`], so it exposes the
/// write queries directly and every read query through `Deref`. **Not `Clone`**: only the
/// committed-block event loop (see [`crate::builder`]) owns it, so writes have a single owner
/// matching SQLite's single-writer model.
pub(crate) struct NtxDbWriter {
    writer: DbWriter,
    reader: NtxDbReader,
}

impl std::ops::Deref for NtxDbWriter {
    type Target = NtxDbReader;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl NtxDbWriter {
    /// Returns a cloneable read-only handle to the same database.
    pub(crate) fn reader(&self) -> NtxDbReader {
        self.reader.clone()
    }

    pub(crate) async fn insert_genesis_chain_state(
        &self,
        genesis_header: BlockHeader,
        genesis_commitment: Word,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("insert_genesis_chain_state", move |tx| {
                queries::insert_genesis_chain_state(tx, &genesis_header, &genesis_commitment)
            })
            .await
    }

    /// Applies a committed block's effects and returns the accounts whose pending feature notes
    /// gained a sponsorship in this block (one entry per sponsorship), so the coordinator can wake
    /// their actors.
    pub(crate) async fn apply_committed_block(
        &self,
        effects: CommittedBlockEffects,
        chain_mmr: PartialMmr,
    ) -> Result<Vec<AccountId>, DatabaseError> {
        self.writer
            .write("apply_committed_block", move |tx| {
                queries::apply_committed_block(tx, &effects, &chain_mmr)
            })
            .await
    }

    pub(crate) async fn notes_failed(
        &self,
        failed_notes: Vec<(Nullifier, NoteError)>,
        block_num: BlockNumber,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("notes_failed", move |tx| queries::notes_failed(tx, &failed_notes, block_num))
            .await
    }

    pub(crate) async fn discard_notes(
        &self,
        nullifiers: Vec<Nullifier>,
        block_num: BlockNumber,
        max_attempts: usize,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("discard_notes", move |tx| {
                queries::discard_notes(
                    tx,
                    &nullifiers,
                    block_num,
                    max_attempts,
                    OVERSIZED_NOTE_DISCARD_REASON,
                )
            })
            .await
    }

    pub(crate) async fn insert_note_scripts(
        &self,
        script_root: Word,
        script: NoteScript,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("insert_note_script", move |tx| {
                queries::insert_note_script(tx, &script_root, &script)
            })
            .await
    }
}

// LIFECYCLE
// ================================================================================================

/// Opens an async connection pool after verifying the database is at the latest schema version.
#[miden_instrument(
    target = COMPONENT,
    name = "ntx_builder.database.load",
    fields(path = database_filepath),
    err,
)]
pub async fn load(database_filepath: PathBuf) -> anyhow::Result<NtxDbWriter> {
    load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Opens an async connection pool with a specific pool size after verifying the database is at the
/// latest schema version.
#[miden_instrument(
    target = COMPONENT,
    name = "ntx_builder.database.load",
    fields(path = database_filepath),
    err,
)]
pub async fn load_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> anyhow::Result<NtxDbWriter> {
    verify_latest_schema(&database_filepath).context("failed to verify database schema")?;

    open_with_pool_size(&database_filepath, connection_pool_size)
}

/// Applies all pending migrations to an existing DB.
#[miden_instrument(target = COMPONENT)]
pub fn migrate(database_filepath: impl AsRef<Path>) -> Result<(), DatabaseError> {
    migrate_database(database_filepath.as_ref())?;
    Ok(())
}

fn open_with_pool_size(
    database_filepath: &Path,
    connection_pool_size: NonZeroUsize,
) -> anyhow::Result<NtxDbWriter> {
    let (writer, reader) =
        miden_node_db::sqlite::open_with_pool_size(database_filepath, connection_pool_size)
            .context("failed to build connection pool")?;

    info!(
        target: COMPONENT,
        "Connected to the database",
        path = database_filepath,
        db.sqlite.connection_pool_size = connection_pool_size.get()
    );

    Ok(NtxDbWriter { writer, reader: NtxDbReader { reader } })
}

/// Creates and initializes the database, then seeds it with the genesis block.
///
/// Mirrors the store's bootstrap: after this completes the singleton `chain_state` row exists at
/// [`BlockNumber::GENESIS`](miden_protocol::block::BlockNumber::GENESIS), so
/// [`crate::NtxBuilderConfig::build`] can assume the genesis block is always present and never has
/// to consume it from the committed-block subscription on startup.
///
/// Returns an error if the database has already been bootstrapped.
#[miden_instrument(
    target = COMPONENT,
    name = "ntx_builder.database.bootstrap",
    fields(path = database_filepath),
    err,
)]
pub async fn bootstrap(database_filepath: PathBuf, genesis: &SignedBlock) -> anyhow::Result<()> {
    bootstrap_database(&database_filepath).context("failed to bootstrap database schema")?;
    let db =
        open_with_pool_size(&database_filepath, miden_node_db::default_connection_pool_size())?;

    let genesis_commitment = genesis.header().commitment();
    let genesis_header = genesis.header().clone();

    db.insert_genesis_chain_state(genesis_header, genesis_commitment)
        .await
        .context("failed to seed genesis chain state")?;

    let effects = CommittedBlockEffects::from_signed_block(genesis);
    db.apply_committed_block(effects, PartialMmr::default())
        .await
        .context("failed to insert genesis block")?;

    Ok(())
}

// TEST HELPERS
// ================================================================================================

/// Creates a schema-migrated (but un-seeded) database backed by a temp file for testing.
///
/// Returns the [`NtxDbWriter`]; tests read through its `Deref` to [`NtxDbReader`] and write
/// directly, and pass `writer.reader()` into components that take a read-only handle.
#[cfg(test)]
pub(crate) async fn test_setup() -> (NtxDbWriter, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("failed to create temp directory");
    let db_path = dir.path().join("test.sqlite3");
    bootstrap_database(&db_path).expect("database should bootstrap");
    let db = load(db_path).await.expect("test DB load should succeed");
    (db, dir)
}

/// Test-only read helpers (raw row counts) — reads, so they live on the reader handle and are
/// reachable from an [`NtxDbWriter`] through `Deref`.
#[cfg(test)]
impl NtxDbReader {
    /// Counts the rows returned by a `SELECT COUNT(*)` statement.
    pub(crate) async fn count(&self, sql: &'static str) -> i64 {
        self.reader
            .read("count", move |tx| {
                let n =
                    tx.query(sql, &[], |row| row.get::<i64>(0))?.into_iter().next().unwrap_or(0);
                Ok::<i64, DatabaseError>(n)
            })
            .await
            .unwrap()
    }

    pub(crate) async fn count_notes(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM notes").await
    }

    pub(crate) async fn count_accounts(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM accounts").await
    }

    pub(crate) async fn count_chain_state(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM chain_state").await
    }

    pub(crate) async fn count_sponsorship_notes(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM sponsorship_notes").await
    }
}

/// Test-only write helpers.
///
/// These wrap writes that have no production [`NtxDbWriter`] method (the individual writes that
/// production code only ever performs as part of [`NtxDbWriter::apply_committed_block`]), so tests
/// still reach the database exclusively through the wrapper.
#[cfg(test)]
impl NtxDbWriter {
    /// Seeds a committed account row (and its `last_tx_id`) for tests that exercise the actor's
    /// landing detection without driving a full committed block.
    pub(crate) async fn upsert_account_for_test(
        &self,
        account_id: AccountId,
        account: Account,
        last_tx_id: TransactionId,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("test_upsert_account", move |tx| {
                queries::upsert_account(tx, account_id, &account, last_tx_id)
            })
            .await
    }

    pub(crate) async fn insert_network_notes(
        &self,
        notes: Vec<AccountTargetNetworkNote>,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("insert_network_notes", move |tx| queries::insert_network_notes(tx, &notes))
            .await
    }

    pub(crate) async fn mark_notes_consumed(
        &self,
        nullifiers: Vec<Nullifier>,
        block_num: BlockNumber,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("mark_notes_consumed", move |tx| {
                queries::mark_notes_consumed(tx, &nullifiers, block_num)
            })
            .await
    }

    pub(crate) async fn insert_sponsorship_notes(
        &self,
        notes: Vec<SponsorshipNote>,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("insert_sponsorship_notes", move |tx| {
                queries::insert_sponsorship_notes(tx, &notes)
            })
            .await
    }

    pub(crate) async fn mark_sponsorships_consumed(
        &self,
        nullifiers: Vec<Nullifier>,
        block_num: BlockNumber,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("mark_sponsorships_consumed", move |tx| {
                queries::mark_sponsorships_consumed(tx, &nullifiers, block_num)
            })
            .await
    }

    pub(crate) async fn update_chain_state_tip(
        &self,
        block_header: BlockHeader,
        chain_mmr: PartialMmr,
    ) -> Result<(), DatabaseError> {
        let block_num = block_header.block_num();
        self.writer
            .write("update_chain_state_tip", move |tx| {
                queries::update_chain_state_tip(tx, block_num, &block_header, &chain_mmr)
            })
            .await
    }

    /// Discards notes with an explicit reason, unlike [`NtxDbWriter::discard_notes`] which always
    /// records [`OVERSIZED_NOTE_DISCARD_REASON`].
    pub(crate) async fn discard_notes_with_reason(
        &self,
        nullifiers: Vec<Nullifier>,
        block_num: BlockNumber,
        max_attempts: usize,
        reason: String,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("discard_notes", move |tx| {
                queries::discard_notes(tx, &nullifiers, block_num, max_attempts, &reason)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    use super::*;
    use crate::test_utils::{mock_genesis_block, mock_genesis_block_with_network_account};

    #[tokio::test]
    async fn bootstrap_seeds_genesis_network_account() {
        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("ntx-builder.sqlite3");

        let (genesis, account_id) = mock_genesis_block_with_network_account();
        bootstrap(db_path.clone(), &genesis)
            .await
            .expect("bootstrap should succeed with a network account in genesis");

        let db = load(db_path).await.expect("load should open the bootstrapped database");
        let account = db.get_account(account_id).await.expect("query should succeed");
        assert!(account.is_some(), "genesis network account should be committed after bootstrap");
    }

    #[tokio::test]
    async fn bootstrap_seeds_genesis_chain_state() {
        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("ntx-builder.sqlite3");
        let genesis = mock_genesis_block();
        let expected_validator_keys =
            GenesisValidatorKeys::from_validator_config(genesis.header().validator_config());

        bootstrap(db_path.clone(), &genesis)
            .await
            .expect("bootstrap should succeed on a fresh database");

        let db = load(db_path).await.expect("load should open the bootstrapped database");
        let (block_num, ..) = db
            .select_chain_state()
            .await
            .expect("query should succeed")
            .expect("chain state should be present after bootstrap");

        assert_eq!(block_num, BlockNumber::GENESIS);
        assert_eq!(
            db.select_genesis_validator_keys()
                .await
                .expect("query should succeed")
                .expect("genesis validator keys should be present"),
            expected_validator_keys,
        );
    }

    #[tokio::test]
    async fn bootstrap_rejects_already_bootstrapped_database() {
        let dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = dir.path().join("ntx-builder.sqlite3");

        bootstrap(db_path.clone(), &mock_genesis_block())
            .await
            .expect("first bootstrap should succeed");

        let err = bootstrap(db_path, &mock_genesis_block())
            .await
            .expect_err("second bootstrap should fail");
        assert!(
            err.chain().any(|source| source.to_string().contains("database already exists")),
            "unexpected error: {err}"
        );
    }
}
