use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::RangeInclusive;
use std::path::PathBuf;

use anyhow::Context;
use diesel::{Connection, QueryableByName, RunQueryDsl, SqliteConnection};
use miden_node_proto::domain::account::{AccountInfo, AccountSummary};
use miden_node_proto::generated as proto;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::Word;
use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader};
use miden_protocol::asset::{Asset, AssetVaultKey};
use miden_protocol::block::{BlockHeader, BlockNoteIndex, BlockNumber, SignedBlock};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    NoteDetails,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteScript,
    Nullifier,
};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::{Deserializable, Serializable};
use tokio::sync::oneshot;
use tracing::{Instrument, info, instrument};

use crate::COMPONENT;
use crate::db::manager::{ConnectionManager, configure_connection_on_creation};
use crate::db::migrations::apply_migrations;
use crate::db::models::conv::SqlTypeConvert;
use crate::db::models::queries::StorageMapValuesPage;
use crate::db::models::{Page, queries};
use crate::errors::{DatabaseError, DatabaseSetupError, NoteSyncError, StateSyncError};
use crate::genesis::GenesisBlock;

pub(crate) mod manager;

mod migrations;
mod schema_hash;

#[cfg(test)]
mod tests;

pub(crate) mod models;

/// [diesel](https://diesel.rs) generated schema
pub(crate) mod schema;

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;

pub struct Db {
    pool: deadpool_diesel::Pool<ConnectionManager, deadpool::managed::Object<ConnectionManager>>,
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
            vault_key: AssetVaultKey::new_unchecked(vault_key),
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
pub struct TransactionSummary {
    pub account_id: AccountId,
    pub block_num: BlockNumber,
    pub transaction_id: TransactionId,
}

#[derive(Debug, PartialEq)]
pub struct TransactionRecord {
    pub block_num: BlockNumber,
    pub transaction_id: TransactionId,
    pub account_id: AccountId,
    pub initial_state_commitment: Word,
    pub final_state_commitment: Word,
    pub nullifiers: Vec<Nullifier>, // Store nullifiers for input notes
    pub output_notes: Vec<NoteId>,  // Store note IDs for output notes
}

impl TransactionRecord {
    /// Convert to proto `TransactionRecord`, but requires note sync records for output notes.
    /// For `sync_transactions` RPC, we need to fetch note sync records separately since we only
    /// store note IDs in the database.
    pub fn into_proto_with_note_records(
        self,
        note_records: Vec<NoteRecord>,
    ) -> proto::rpc::TransactionRecord {
        let output_notes = Vec::from_iter(note_records.into_iter().map(Into::into));

        proto::rpc::TransactionRecord {
            header: Some(proto::transaction::TransactionHeader {
                account_id: Some(self.account_id.into()),
                initial_state_commitment: Some(self.initial_state_commitment.into()),
                final_state_commitment: Some(self.final_state_commitment.into()),
                nullifiers: self.nullifiers.into_iter().map(From::from).collect(),
                output_notes,
            }),
            block_num: self.block_num.as_u32(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NoteRecord {
    pub block_num: BlockNumber,
    pub note_index: BlockNoteIndex,
    pub note_id: Word,
    pub note_commitment: Word,
    pub metadata: NoteMetadata,
    pub details: Option<NoteDetails>,
    pub inclusion_path: SparseMerklePath,
}

impl From<NoteRecord> for proto::note::CommittedNote {
    fn from(note: NoteRecord) -> Self {
        let inclusion_proof = Some(proto::note::NoteInclusionInBlockProof {
            note_id: Some(note.note_id.into()),
            block_num: note.block_num.as_u32(),
            note_index_in_block: note.note_index.leaf_index_value().into(),
            inclusion_path: Some(Into::into(note.inclusion_path)),
        });
        let note = Some(proto::note::Note {
            metadata: Some(note.metadata.into()),
            details: note.details.map(|details| details.to_bytes()),
        });
        Self { inclusion_proof, note }
    }
}

impl From<NoteRecord> for proto::note::NoteSyncRecord {
    fn from(value: NoteRecord) -> Self {
        let note_id = value.note_id.into();
        let note_index_in_block = value.note_index.leaf_index_value().into();
        let metadata = value.metadata.into();
        let inclusion_path = value.inclusion_path.into();

        proto::note::NoteSyncRecord {
            note_id: Some(note_id),
            note_index_in_block,
            metadata: Some(metadata),
            inclusion_path: Some(inclusion_path),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct StateSyncUpdate {
    pub notes: Vec<NoteSyncRecord>,
    pub block_header: BlockHeader,
    pub account_updates: Vec<AccountSummary>,
    pub transactions: Vec<TransactionSummary>,
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
    pub note_id: Word,
    pub metadata: NoteMetadata,
    pub inclusion_path: SparseMerklePath,
}

impl From<NoteSyncRecord> for proto::note::NoteSyncRecord {
    fn from(note: NoteSyncRecord) -> Self {
        Self {
            note_index_in_block: note.note_index.leaf_index_value().into(),
            note_id: Some(note.note_id.into()),
            metadata: Some(note.metadata.into()),
            inclusion_path: Some(Into::into(note.inclusion_path)),
        }
    }
}

impl From<NoteRecord> for NoteSyncRecord {
    fn from(note: NoteRecord) -> Self {
        Self {
            block_num: note.block_num,
            note_index: note.note_index,
            note_id: note.note_id,
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
    pub fn bootstrap(database_filepath: PathBuf, genesis: &GenesisBlock) -> anyhow::Result<()> {
        // Create database.
        //
        // This will create the file if it does not exist, but will also happily open it if already
        // exists. In the latter case we will error out when attempting to insert the genesis
        // block so this isn't such a problem.
        let mut conn: SqliteConnection = diesel::sqlite::SqliteConnection::establish(
            database_filepath.to_str().context("database filepath is invalid")?,
        )
        .context("failed to open a database connection")?;

        configure_connection_on_creation(&mut conn)?;

        // Run migrations.
        apply_migrations(&mut conn).context("failed to apply database migrations")?;

        // Insert genesis block data.
        let genesis = genesis.inner();
        conn.transaction(move |conn| {
            models::queries::apply_block(
                conn,
                genesis.header(),
                genesis.signature(),
                &[],
                &[],
                genesis.body().updated_accounts(),
                genesis.body().transactions(),
            )
        })
        .context("failed to insert genesis block")?;
        Ok(())
    }

    /// Create and commit a transaction with the queries added in the provided closure
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

    /// Run the query _without_ a transaction
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
            .await
            .map_err(|e| DatabaseError::ConnectionPoolObtainError(Box::new(e)))?;

        conn.interact(move |conn| {
            let r = query(conn)?;
            Ok(r)
        })
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }

    /// Open a connection to the DB and apply any pending migrations.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(database_filepath: PathBuf) -> Result<Self, DatabaseSetupError> {
        let manager = ConnectionManager::new(database_filepath.to_str().unwrap());
        let pool = deadpool_diesel::Pool::builder(manager).max_size(16).build()?;

        info!(
            target: COMPONENT,
            sqlite= %database_filepath.display(),
            "Connected to the database"
        );

        let me = Db { pool };
        me.query("migrations", apply_migrations).await?;
        Ok(me)
    }

    /// Loads all the nullifiers from the DB.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub(crate) async fn select_all_nullifiers(&self) -> Result<Vec<NullifierInfo>> {
        self.transact("all nullifiers", move |conn| {
            let nullifiers = queries::select_all_nullifiers(conn)?;
            Ok(nullifiers)
        })
        .await
    }

    /// Loads the nullifiers that match the prefixes from the DB.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
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
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
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

    /// Loads multiple block headers from the DB.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
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
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_all_block_headers(&self) -> Result<Vec<BlockHeader>> {
        self.transact("all block headers", |conn| {
            let raw = queries::select_all_block_headers(conn)?;
            Ok(raw)
        })
        .await
    }

    /// TODO marked for removal, replace with paged version
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_all_account_commitments(&self) -> Result<Vec<(AccountId, Word)>> {
        self.transact("read all account commitments", move |conn| {
            queries::select_all_account_commitments(conn)
        })
        .await
    }

    /// Returns all account IDs that have public state.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_all_public_account_ids(&self) -> Result<Vec<AccountId>> {
        self.transact("read all public account IDs", move |conn| {
            queries::select_all_public_account_ids(conn)
        })
        .await
    }

    /// Loads public account details from the DB.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_account(&self, id: AccountId) -> Result<AccountInfo> {
        self.transact("Get account details", move |conn| queries::select_account(conn, id))
            .await
    }

    /// Loads public account details for a network account by its full account ID.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_network_account_by_id(
        &self,
        account_id: AccountId,
    ) -> Result<Option<AccountInfo>> {
        self.transact("Get network account by id", move |conn| {
            queries::select_network_account_by_id(conn, account_id)
        })
        .await
    }

    /// Returns network account IDs within the specified block range (based on account creation
    /// block).
    ///
    /// The function may return fewer accounts than exist in the range if the result would exceed
    /// `MAX_RESPONSE_PAYLOAD_BYTES / AccountId::SERIALIZED_SIZE` rows. In this case, the result is
    /// truncated at a block boundary to ensure all accounts from included blocks are returned.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A vector of network account IDs.
    /// - The last block number that was fully included in the result. When truncated, this will be
    ///   less than the requested range end.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_all_network_account_ids(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<AccountId>, BlockNumber)> {
        self.transact("Get all network account IDs", move |conn| {
            queries::select_all_network_account_ids(conn, block_range)
        })
        .await
    }

    /// Queries vault assets at a specific block
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_account_vault_at_block(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<Vec<Asset>> {
        self.transact("Get account vault at block", move |conn| {
            queries::select_account_vault_at_block(conn, account_id, block_num)
        })
        .await
    }

    /// Queries the account code by its commitment hash.
    ///
    /// Returns `None` if no code exists with that commitment.
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

    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn get_state_sync(
        &self,
        block_number: BlockNumber,
        account_ids: Vec<AccountId>,
        note_tags: Vec<u32>,
    ) -> Result<StateSyncUpdate, StateSyncError> {
        self.transact::<StateSyncUpdate, StateSyncError, _, _>("state sync", move |conn| {
            queries::get_state_sync(conn, block_number, account_ids, note_tags)
        })
        .await
    }

    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn get_note_sync(
        &self,
        block_range: RangeInclusive<BlockNumber>,
        note_tags: Vec<u32>,
    ) -> Result<(NoteSyncUpdate, BlockNumber), NoteSyncError> {
        self.transact("notes sync task", move |conn| {
            queries::get_note_sync(conn, note_tags.as_slice(), block_range)
        })
        .await
    }

    /// Loads all the [`miden_protocol::note::Note`]s matching a certain [`NoteId`] from the
    /// database.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn select_notes_by_id(&self, note_ids: Vec<NoteId>) -> Result<Vec<NoteRecord>> {
        self.transact("note by id", move |conn| {
            queries::select_notes_by_id(conn, note_ids.as_slice())
        })
        .await
    }

    /// Returns all note commitments from the DB that match the provided ones.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
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
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
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
            models::queries::apply_block(
                conn,
                signed_block.header(),
                signed_block.signature(),
                &notes,
                signed_block.body().created_nullifiers(),
                signed_block.body().updated_accounts(),
                signed_block.body().transactions(),
            )?;

            // XXX FIXME TODO free floating mutex MUST NOT exist
            // it doesn't bind it properly to the data locked!
            if allow_acquire.send(()).is_err() {
                tracing::warn!(target: COMPONENT, "failed to send notification for successful block application, potential deadlock");
            }

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
    ) -> Result<StorageMapValuesPage> {
        self.transact("select storage map sync values", move |conn| {
            models::queries::select_account_storage_map_values(conn, account_id, block_range)
        })
        .await
    }

    /// Emits size metrics for each table in the database, and the entire database.
    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn analyze_table_sizes(&self) -> Result<(), DatabaseError> {
        self.transact("db analysis", |conn| {
            #[derive(QueryableByName)]
            struct TotalSize {
                #[diesel(sql_type = diesel::sql_types::BigInt)]
                size: i64,
            }

            #[derive(QueryableByName)]
            struct Table {
                #[diesel(sql_type = diesel::sql_types::Text)]
                name: String,
                #[diesel(sql_type = diesel::sql_types::BigInt)]
                size: i64,
            }

            let tables =
                diesel::sql_query("SELECT name, sum(payload) AS size FROM dbstat GROUP BY name")
                    .load::<Table>(conn)?;

            let span = tracing::Span::current();
            for Table { name, size } in tables {
                span.set_attribute(format!("database.table.{name}.size"), size);
            }

            let total = diesel::sql_query(
                "SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()",
            )
            .get_result::<TotalSize>(conn)?;
            span.set_attribute("database.total.size", total.size);

            Result::<_, DatabaseError>::Ok(())
        })
        .await
        .inspect_err(|err| tracing::Span::current().set_error(err))?;

        Ok(())
    }

    /// Loads the network notes for an account that are unconsumed by a specified block number.
    /// Pagination is used to limit the number of notes returned.
    pub(crate) async fn select_unconsumed_network_notes(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        page: Page,
    ) -> Result<(Vec<NoteRecord>, Page)> {
        self.transact("unconsumed network notes for account", move |conn| {
            models::queries::select_unconsumed_network_notes_by_account_id(
                conn, account_id, block_num, page,
            )
        })
        .await
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
