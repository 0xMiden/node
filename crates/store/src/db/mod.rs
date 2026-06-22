use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut, RangeInclusive};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use diesel::{Connection, SqliteConnection};
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_node_proto::domain::account::AccountInfo;
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::Word;
use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader, StorageMapKey};
use miden_protocol::asset::{Asset, AssetVaultKey};
use miden_protocol::block::{BlockHeader, BlockNoteIndex, BlockNumber, SignedBlock};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    NoteAttachments,
    NoteDetails,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteScript,
    Nullifier,
};
use miden_protocol::transaction::TransactionHeader;
use miden_protocol::utils::serde::Deserializable;
use tokio::sync::oneshot;
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::db::migrations::{migrate_database, verify_latest_schema};
use crate::db::models::conv::SqlTypeConvert;
use crate::db::models::queries;
pub use crate::db::models::queries::{
    AccountCommitmentsPage,
    NullifiersPage,
    PublicAccountIdsPage,
    PublicAccountStateRootsPage,
};
use crate::db::models::queries::{BlockHeaderCommitment, StorageMapValuesPage};
use crate::errors::{DatabaseError, NoteSyncError};
use crate::genesis::GenesisBlock;

const STORAGE_MAP_VALUE_PER_ROW_BYTES: usize =
    2 * size_of::<Word>() + size_of::<u32>() + size_of::<u8>();

fn default_storage_map_entries_limit() -> usize {
    MAX_RESPONSE_PAYLOAD_BYTES / STORAGE_MAP_VALUE_PER_ROW_BYTES
}

mod migrations;
#[cfg(test)]
pub(crate) use migrations::bootstrap_database;

#[cfg(test)]
mod tests;

pub(crate) mod models;

/// [diesel](https://diesel.rs) generated schema
///
/// The ignored `diesel_schema_is_in_sync_with_migrations` test verifies that this file matches the
/// schema produced by the current migrations.
pub(crate) mod schema;

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;

/// Database options used by the store state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DatabaseOptions {
    /// Maximum number of SQLite connections in the connection pool.
    pub connection_pool_size: NonZeroUsize,
}

impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            connection_pool_size: miden_node_db::default_connection_pool_size(),
        }
    }
}

/// The Store's database.
///
/// Extends the underlying [`miden_node_db::Db`] type with functionality specific to the Store.
pub struct Db {
    db: miden_node_db::Db,
}

impl Deref for Db {
    type Target = miden_node_db::Db;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for Db {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

/// Describes the value of an asset for an account ID at `block_num` specifically.
///
/// If `asset` is `None`, the asset was removed.
#[derive(Debug, Clone)]
pub struct AccountVaultValue {
    pub block_num: BlockNumber,
    pub vault_key: AssetVaultKey,
    /// None if the asset was removed
    pub asset: Option<Asset>,
}

impl AccountVaultValue {
    pub fn from_raw_row(row: (i64, Vec<u8>, Option<Vec<u8>>)) -> Result<Self, DatabaseError> {
        let (block_num, vault_key, asset) = row;
        let vault_key = Word::read_from_bytes(&vault_key)?;
        Ok(Self {
            block_num: BlockNumber::from_raw_sql(block_num)?,
            vault_key: AssetVaultKey::try_from(vault_key)?,
            asset: asset.map(|b| Asset::read_from_bytes(&b)).transpose()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct NullifierInfo {
    pub nullifier: Nullifier,
    pub block_num: BlockNumber,
}

impl PartialEq<(Nullifier, BlockNumber)> for NullifierInfo {
    fn eq(&self, (nullifier, block_num): &(Nullifier, BlockNumber)) -> bool {
        &self.nullifier == nullifier && &self.block_num == block_num
    }
}

#[derive(Debug, PartialEq)]
pub struct TransactionRecord {
    pub block_num: BlockNumber,
    pub header: TransactionHeader,
    /// Inclusion proofs for committed output notes. Notes in `header.output_notes()` without a
    /// corresponding proof here were erased (created and consumed within the same batch).
    pub output_note_proofs: Vec<NoteSyncRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NoteRecord {
    pub block_num: BlockNumber,
    pub note_index: BlockNoteIndex,
    pub note_id: Word,
    pub metadata: NoteMetadata,
    pub details: Option<NoteDetails>,
    pub attachments: NoteAttachments,
    pub inclusion_path: SparseMerklePath,
}

#[derive(Debug, PartialEq)]
pub struct NoteSyncUpdate {
    pub notes: Vec<NoteSyncRecord>,
    pub block_header: BlockHeader,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NoteSyncRecord {
    pub block_num: BlockNumber,
    pub note_index: BlockNoteIndex,
    pub note_id: NoteId,
    pub metadata: NoteMetadata,
    pub inclusion_path: SparseMerklePath,
}

impl From<NoteRecord> for NoteSyncRecord {
    fn from(note: NoteRecord) -> Self {
        Self {
            block_num: note.block_num,
            note_index: note.note_index,
            note_id: NoteId::from_raw(note.note_id),
            metadata: note.metadata,
            inclusion_path: note.inclusion_path,
        }
    }
}

impl Db {
    /// Creates a new database and inserts the genesis block.
    #[instrument(
        target = COMPONENT,
        name = "store.database.bootstrap",
        skip_all,
        fields(path=%database_filepath.display())
        err,
    )]
    pub fn bootstrap(database_filepath: PathBuf, genesis: GenesisBlock) -> anyhow::Result<()> {
        migrations::bootstrap_database(&database_filepath)
            .context("failed to bootstrap database schema")?;

        let mut conn: SqliteConnection = diesel::sqlite::SqliteConnection::establish(
            database_filepath.to_str().context("database filepath is invalid")?,
        )
        .context("failed to open a database connection")?;

        miden_node_db::configure_connection_on_creation(&mut conn)?;

        // Insert genesis block data.
        let genesis_block = genesis.into_inner();
        conn.transaction(move |conn| models::queries::apply_block(conn, &genesis_block, &[]))
            .context("failed to insert genesis block")?;
        Ok(())
    }

    /// Open a connection to the DB after verifying that it is at the latest schema version.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(database_filepath: PathBuf) -> Result<Self, DatabaseError> {
        Self::load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size())
            .await
    }

    /// Open a connection to the DB with a specific pool size after verifying that it is at the
    /// latest schema version.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load_with_pool_size(
        database_filepath: PathBuf,
        connection_pool_size: NonZeroUsize,
    ) -> Result<Self, DatabaseError> {
        verify_latest_schema(&database_filepath)?;

        let db = miden_node_db::Db::new_with_pool_size(&database_filepath, connection_pool_size)?;
        info!(
            target: COMPONENT,
            sqlite= %database_filepath.display(),
            connection_pool_size = %connection_pool_size,
            "Connected to the database"
        );

        Ok(Self { db })
    }

    /// Applies all pending migrations to an existing DB.
    #[instrument(target = COMPONENT, skip_all)]
    pub fn migrate(database_filepath: impl AsRef<Path>) -> Result<(), DatabaseError> {
        migrate_database(database_filepath.as_ref())?;
        Ok(())
    }

    /// Returns a page of nullifiers for tree rebuilding.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_nullifiers_paged(
        &self,
        page_size: std::num::NonZeroUsize,
        after_nullifier: Option<Nullifier>,
    ) -> Result<NullifiersPage> {
        self.transact("read nullifiers paged", move |conn| {
            queries::select_nullifiers_paged(conn, page_size, after_nullifier)
        })
        .await
    }

    /// Loads the nullifiers that match the prefixes from the DB.
    #[instrument(
        level = "debug",
        target = COMPONENT,
        skip_all,
        fields(prefix_len, prefixes = nullifier_prefixes.len()),
        err
    )]
    pub async fn select_nullifiers_by_prefix(
        &self,
        prefix_len: u32,
        nullifier_prefixes: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<NullifierInfo>, BlockNumber)> {
        assert_eq!(prefix_len, 16, "Only 16-bit prefixes are supported");

        self.transact("nullifieres by prefix", move |conn| {
            let nullifier_prefixes =
                Vec::from_iter(nullifier_prefixes.into_iter().map(|prefix| prefix as u16));
            queries::select_nullifiers_by_prefix(
                conn,
                prefix_len as u8,
                &nullifier_prefixes[..],
                block_range,
            )
        })
        .await
    }

    /// Search for a [`BlockHeader`] from the database by its `block_num`.
    ///
    /// When `block_number` is [None], the latest block header is returned.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_block_header_by_block_num(
        &self,
        maybe_block_number: Option<BlockNumber>,
    ) -> Result<Option<BlockHeader>> {
        self.transact("block headers by block number", move |conn| {
            let val = queries::select_block_header_by_block_num(conn, maybe_block_number)?;
            Ok(val)
        })
        .await
    }

    /// Search for a [`BlockHeader`] and its [`Signature`] from the database by its `block_num`.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_block_header_and_signature_by_block_num(
        &self,
        block_number: BlockNumber,
    ) -> Result<Option<(BlockHeader, Signature)>> {
        self.transact("block headers and signature by block number", move |conn| {
            let val = queries::select_block_header_and_signature_by_block_num(conn, block_number)?;
            Ok(val)
        })
        .await
    }

    /// Loads multiple block headers from the DB.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_block_headers(
        &self,
        blocks: impl Iterator<Item = BlockNumber> + Send + 'static,
    ) -> Result<Vec<BlockHeader>> {
        self.transact("block headers from given block numbers", move |conn| {
            let raw = queries::select_block_headers(conn, blocks)?;
            Ok(raw)
        })
        .await
    }

    /// Loads all the block headers from the DB.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_all_block_header_commitments(&self) -> Result<Vec<BlockHeaderCommitment>> {
        self.transact("all block headers", |conn| {
            let raw = queries::select_all_block_header_commitments(conn)?;
            Ok(raw)
        })
        .await
    }

    /// Returns a page of account commitments for tree rebuilding.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_account_commitments_paged(
        &self,
        page_size: std::num::NonZeroUsize,
        after_account_id: Option<AccountId>,
    ) -> Result<AccountCommitmentsPage> {
        self.transact("read account commitments paged", move |conn| {
            queries::select_account_commitments_paged(conn, page_size, after_account_id)
        })
        .await
    }

    /// Returns a page of public account IDs for forest rebuilding.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_public_account_ids_paged(
        &self,
        page_size: std::num::NonZeroUsize,
        after_account_id: Option<AccountId>,
    ) -> Result<PublicAccountIdsPage> {
        self.transact("read public account IDs paged", move |conn| {
            queries::select_public_account_ids_paged(conn, page_size, after_account_id)
        })
        .await
    }

    /// Returns a page of public account state roots for forest consistency verification.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_public_account_state_roots_paged(
        &self,
        page_size: std::num::NonZeroUsize,
        after_account_id: Option<AccountId>,
    ) -> Result<PublicAccountStateRootsPage> {
        self.transact("read public account state roots paged", move |conn| {
            queries::select_public_account_state_roots_paged(conn, page_size, after_account_id)
        })
        .await
    }

    /// Loads public account details from the DB.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_account(&self, id: AccountId) -> Result<AccountInfo> {
        self.transact("Get account details", move |conn| queries::select_account(conn, id))
            .await
    }

    /// Returns the subset of the provided account IDs that classify as network accounts.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_network_accounts_subset(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<HashSet<AccountId>> {
        self.transact("Filter network accounts subset", move |conn| {
            queries::select_network_accounts_subset(conn, &account_ids)
        })
        .await
    }

    /// Queries the account code by its commitment hash.
    ///
    /// Returns `None` if no code exists with that commitment.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn select_account_code_by_commitment(
        &self,
        code_commitment: Word,
    ) -> Result<Option<Vec<u8>>> {
        self.transact("Get account code by commitment", move |conn| {
            queries::select_account_code_by_commitment(conn, code_commitment)
        })
        .await
    }

    /// Queries the account header and storage header for a specific account at a block.
    ///
    /// Returns both in a single query to avoid querying the database twice.
    /// Returns `None` if the account doesn't exist at that block.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn select_account_header_with_storage_header_at_block(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<Option<(AccountHeader, AccountStorageHeader)>> {
        self.transact("Get account header with storage header at block", move |conn| {
            queries::select_account_header_with_storage_header_at_block(conn, account_id, block_num)
        })
        .await
    }

    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn get_note_sync_multi(
        &self,
        block_range: RangeInclusive<BlockNumber>,
        note_tags: Arc<[u32]>,
    ) -> Result<Vec<NoteSyncUpdate>, NoteSyncError> {
        self.transact("notes sync task", move |conn| {
            queries::get_note_sync_multi(conn, &note_tags, block_range, MAX_RESPONSE_PAYLOAD_BYTES)
        })
        .await
    }

    /// Loads all the [`miden_protocol::note::Note`]s matching a certain [`NoteId`] from the
    /// database.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_notes_by_id(&self, note_ids: Vec<NoteId>) -> Result<Vec<NoteRecord>> {
        self.transact("note by id", move |conn| {
            queries::select_notes_by_id(conn, note_ids.as_slice())
        })
        .await
    }

    /// Returns all note commitments from the DB that match the provided ones.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_existing_note_commitments(
        &self,
        note_commitments: Vec<Word>,
    ) -> Result<HashSet<Word>> {
        self.transact("note by commitment", move |conn| {
            queries::select_existing_note_commitments(conn, note_commitments.as_slice())
        })
        .await
    }

    /// Loads inclusion proofs for notes matching the given note commitments.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn select_note_inclusion_proofs(
        &self,
        note_commitments: BTreeSet<Word>,
    ) -> Result<BTreeMap<NoteId, NoteInclusionProof>> {
        self.transact("block note inclusion proofs by commitment", move |conn| {
            models::queries::select_note_inclusion_proofs(conn, &note_commitments)
        })
        .await
    }

    /// Inserts the data of a new block into the DB.
    ///
    /// `allow_acquire` and `acquire_done` are used to synchronize writes to the DB with writes to
    /// the in-memory trees. Further details available on [`super::state::State::apply_block`].
    // TODO: This span is logged in a root span, we should connect it to the parent one.
    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn apply_block(
        &self,
        allow_acquire: oneshot::Sender<()>,
        acquire_done: oneshot::Receiver<()>,
        signed_block: SignedBlock,
        notes: Vec<(NoteRecord, Option<Nullifier>)>,
    ) -> Result<()> {
        self.transact("apply block", move |conn| -> Result<()> {
            models::queries::apply_block(conn, &signed_block, &notes)?;

            // XXX FIXME TODO free floating mutex MUST NOT exist it doesn't bind it properly to the
            // data locked!
            {
                let _span = tracing::info_span!(target: COMPONENT, "acquire_write_lock").entered();
                if allow_acquire.send(()).is_err() {
                    tracing::warn!(target: COMPONENT, "failed to send notification for successful block application, potential deadlock");
                }
            }

            models::queries::prune_history(conn, signed_block.header().block_num())?;

            let _span =
                tracing::info_span!(target: COMPONENT, "acquire_done_lock").entered();
            acquire_done.blocking_recv()?;

            Ok(())
        })
        .await
    }

    /// Selects storage map values for syncing storage maps for a specific account ID.
    ///
    /// The returned values are the latest known values up to `block_range.end()`, and no values
    /// earlier than `block_range.start()` are returned.
    pub(crate) async fn select_storage_map_sync_values(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
        entries_limit: Option<usize>,
    ) -> Result<StorageMapValuesPage> {
        let entries_limit = entries_limit.unwrap_or_else(default_storage_map_entries_limit);

        self.transact("select storage map sync values", move |conn| {
            models::queries::select_account_storage_map_values_paged(
                conn,
                account_id,
                block_range,
                entries_limit,
            )
        })
        .await
    }

    /// Reconstructs storage map details from the database for a specific slot at a block.
    ///
    /// Used as fallback when `AccountStateForest` cache misses (historical or evicted queries).
    /// Rebuilds all entries by querying the DB and filtering to the specific slot.
    ///
    /// Returns:
    ///     - `::LimitExceeded` when too many entries are present
    ///     - `::AllEntries` if the size is less than or equal given `entries_limit`, if any
    #[instrument(target = COMPONENT, skip_all)]
    pub(crate) async fn reconstruct_storage_map_from_db(
        &self,
        account_id: AccountId,
        slot_name: miden_protocol::account::StorageSlotName,
        block_num: BlockNumber,
        entries_limit: Option<usize>,
    ) -> Result<miden_node_proto::domain::account::AccountStorageMapDetails> {
        use miden_node_proto::domain::account::{AccountStorageMapDetails, StorageMapEntries};
        use miden_protocol::EMPTY_WORD;

        // TODO this remains expensive with a large history until we implement pruning for DB
        // columns
        let mut values = Vec::new();
        let mut block_range_start = BlockNumber::GENESIS;
        let entries_limit = entries_limit.unwrap_or_else(default_storage_map_entries_limit);

        let mut page = self
            .select_storage_map_sync_values(
                account_id,
                block_range_start..=block_num,
                Some(entries_limit),
            )
            .await?;

        values.extend(page.values);
        let mut last_block_included = page.last_block_included;

        // If the first page returned no values, the block at block_range_start has more entries
        // than the limit allows (e.g. genesis accounts with large storage maps).
        if values.is_empty() && last_block_included == block_range_start {
            return Ok(AccountStorageMapDetails::limit_exceeded(slot_name));
        }

        loop {
            if page.last_block_included == block_num || page.last_block_included < block_range_start
            {
                break;
            }

            block_range_start = page.last_block_included.child();
            page = self
                .select_storage_map_sync_values(
                    account_id,
                    block_range_start..=block_num,
                    Some(entries_limit),
                )
                .await?;

            if page.last_block_included <= last_block_included {
                return Ok(AccountStorageMapDetails::limit_exceeded(slot_name));
            }

            last_block_included = page.last_block_included;
            values.extend(page.values);
        }

        if page.last_block_included != block_num {
            return Ok(AccountStorageMapDetails::limit_exceeded(slot_name));
        }

        // Filter to the specific slot and collect latest values per key
        let mut latest_values = BTreeMap::<StorageMapKey, Word>::new();
        for value in values {
            if value.slot_name == slot_name {
                let raw_key = value.key;
                latest_values.insert(raw_key, value.value);
            }
        }

        // Remove EMPTY_WORD entries (deletions)
        latest_values.retain(|_, v| *v != EMPTY_WORD);

        if latest_values.len() > AccountStorageMapDetails::MAX_RETURN_ENTRIES {
            return Ok(AccountStorageMapDetails::limit_exceeded(slot_name));
        }

        let entries = Vec::from_iter(latest_values.into_iter());
        Ok(AccountStorageMapDetails {
            slot_name,
            entries: StorageMapEntries::AllEntries(entries),
        })
    }

    pub async fn get_account_vault_sync(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<AccountVaultValue>)> {
        self.transact("account vault sync", move |conn| {
            queries::select_account_vault_assets(conn, account_id, block_range)
        })
        .await
    }

    /// Returns the script for a note by its root.
    pub async fn select_note_script_by_root(&self, root: Word) -> Result<Option<NoteScript>> {
        self.transact("note script by root", move |conn| {
            queries::select_note_script_by_root(conn, root)
        })
        .await
    }

    /// Returns the complete transaction records for the specified accounts within the specified
    /// block range, including state commitments and note IDs.
    ///
    /// Note: This method is size-limited (~5MB) and may not return all matching transactions
    /// if the limit is exceeded. Transactions from partial blocks are excluded to maintain
    /// consistency.
    pub async fn select_transactions_records(
        &self,
        account_ids: Vec<AccountId>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<TransactionRecord>)> {
        self.transact("full transactions records", move |conn| {
            queries::select_transactions_records(conn, &account_ids, block_range)
        })
        .await
    }
}
