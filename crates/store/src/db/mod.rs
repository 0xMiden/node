use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;

use anyhow::Context;
use futures::{Stream, TryStreamExt};
use miden_node_db::sqlite::{DbReader, DbWriter, WriteTx};
use miden_node_proto::domain::account::AccountInfo;
use miden_node_tracing::{info, miden_instrument, warn};
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamLimiter,
    QueryParamNoteCommitmentLimit,
};
use miden_protocol::Word;
use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader, StorageMapKey};
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockHeader,
    BlockNoteIndex,
    BlockNumber,
    BlockSignatures,
    SignedBlock,
};
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
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::TransactionHeader;

use crate::db::migrations::{migrate_database, verify_latest_schema};
use crate::db::pagination::{Page, Paginated};
pub use crate::db::queries::{
    HISTORICAL_BLOCK_RETENTION,
    PrecomputedPublicAccountState,
    PrecomputedPublicAccountStates,
};
use crate::errors::DatabaseError;
use crate::genesis::GenesisBlock;
use crate::state::ScopedBlockNum;
use crate::{COMPONENT, LOG_TARGET};

const STORAGE_MAP_VALUE_PER_ROW_BYTES: usize =
    2 * size_of::<Word>() + size_of::<u32>() + size_of::<u8>();

pub(crate) fn default_storage_map_entries_limit() -> usize {
    MAX_RESPONSE_PAYLOAD_BYTES / STORAGE_MAP_VALUE_PER_ROW_BYTES
}

mod migrations;
#[cfg(test)]
pub(crate) use migrations::bootstrap_database;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_db;
#[cfg(test)]
pub(crate) use test_db::TestDb;

/// Query functions on the `miden-node-db` SQLite framework.
pub(crate) mod queries;

pub(crate) mod pagination;

mod utils;

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
/// Every write serializes on the single framework writer connection. Every read runs on the
/// framework reader pool.
pub struct Db {
    writer: DbWriter,
    reader: DbReader,
}

/// Inserts the genesis block and the protocol configuration that it activates.
fn insert_genesis(tx: &WriteTx<'_>, genesis: GenesisBlock) -> Result<()> {
    let (genesis_block, protocol_config) = genesis.into_parts();
    // The genesis block has no transactions, but it creates every account it contains.
    let new_account_ids = genesis_block
        .body()
        .updated_accounts()
        .iter()
        .map(BlockAccountUpdate::account_id)
        .collect();
    queries::insert_protocol_config(tx, &protocol_config, BlockNumber::GENESIS)?;
    queries::apply_block(
        tx,
        &genesis_block,
        &[],
        &PrecomputedPublicAccountStates::new(),
        &new_account_ids,
    )?;
    Ok(())
}

/// The commitment of a [`BlockHeader`], stored alongside the header it belongs to.
///
/// Keeping it in its own column lets the chain MMR be rebuilt at startup without deserializing
/// every header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct BlockHeaderCommitment(pub(crate) Word);

impl BlockHeaderCommitment {
    pub fn new(header: &BlockHeader) -> Self {
        Self(header.commitment())
    }

    pub fn word(self) -> Word {
        self.0
    }
}

/// Describes the value of an asset for an account ID at `block_num` specifically.
///
/// If `asset` is `None`, the asset was removed.
#[derive(Debug, Clone)]
pub struct AccountVaultValue {
    pub block_num: BlockNumber,
    pub vault_key: AssetId,
    /// None if the asset was removed
    pub asset: Option<Asset>,
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
    /// Maps each consumed input note's nullifier to its note ID, for public notes the node could
    /// resolve. This is to enable the recover of notes by their id.
    pub consumed_note_refs: Vec<(Nullifier, NoteId)>,
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
    pub attachments: NoteAttachments,
    pub inclusion_path: SparseMerklePath,
}

impl From<NoteRecord> for NoteSyncRecord {
    fn from(note: NoteRecord) -> Self {
        Self {
            block_num: note.block_num,
            note_index: note.note_index,
            note_id: NoteId::from_raw(note.note_id),
            metadata: note.metadata,
            attachments: note.attachments,
            inclusion_path: note.inclusion_path,
        }
    }
}

impl Db {
    /// Creates a new database and inserts the genesis block.
    #[miden_instrument(
        target = COMPONENT,
        name = "store.database.bootstrap",
        fields(path = database_filepath),
        err,
    )]
    pub async fn bootstrap(
        database_filepath: PathBuf,
        genesis: GenesisBlock,
    ) -> anyhow::Result<()> {
        migrations::bootstrap_database(&database_filepath)
            .context("failed to bootstrap database schema")?;

        let (writer, _reader) = miden_node_db::sqlite::open(&database_filepath)
            .context("failed to open a database connection")?;

        // Insert genesis block data.
        writer
            .write("insert genesis block", move |tx| insert_genesis(tx, genesis))
            .await
            .context("failed to insert genesis block")?;
        Ok(())
    }

    /// Open a connection to the DB after verifying that it is at the latest schema version.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub async fn load(database_filepath: PathBuf) -> Result<Self, DatabaseError> {
        Self::load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size())
            .await
    }

    /// Open a connection to the DB with a specific pool size after verifying that it is at the
    /// latest schema version.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub async fn load_with_pool_size(
        database_filepath: PathBuf,
        connection_pool_size: NonZeroUsize,
    ) -> Result<Self, DatabaseError> {
        verify_latest_schema(&database_filepath)?;

        let (writer, reader) =
            miden_node_db::sqlite::open_with_pool_size(&database_filepath, connection_pool_size)?;
        info!(
            target: LOG_TARGET,
            "Connected to the database",
            path = database_filepath,
            db.sqlite.connection_pool_size = connection_pool_size.get()
        );

        Ok(Self { writer, reader })
    }

    /// The write handle, for tests that need to seed or corrupt rows no production method writes.
    #[cfg(test)]
    pub(crate) fn writer(&self) -> &DbWriter {
        &self.writer
    }

    /// Selects a protocol configuration by its commitment.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_protocol_config_by_commitment(
        &self,
        commitment: Word,
    ) -> Result<Option<ProtocolConfig>> {
        self.reader
            .read("protocol config by commitment", move |tx| {
                queries::select_protocol_config_by_commitment(tx, commitment)
            })
            .await
    }

    /// Selects the configuration commitment active at the specified block.
    pub async fn select_protocol_config_commitment_at(
        &self,
        block_number: ScopedBlockNum,
    ) -> Result<Option<Word>> {
        self.reader
            .read("protocol config commitment at block", move |tx| {
                queries::select_protocol_config_commitment_at(tx, *block_number)
            })
            .await
    }

    /// Applies all pending migrations to an existing DB.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub fn migrate(database_filepath: impl AsRef<Path>) -> Result<(), DatabaseError> {
        migrate_database(database_filepath.as_ref())?;
        Ok(())
    }

    /// Reads the page of `query` that starts at `next`.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub(crate) async fn page<Q: Paginated>(
        &self,
        query: Q,
        next: Q::Cursor,
    ) -> Result<Page<Q::Item, Q::Cursor>> {
        self.reader
            .read(std::any::type_name::<Q>(), move |tx| query.page(tx, &next))
            .await
    }

    /// Streams the items of every non-empty page of `query` in order, starting at `start` and
    /// ending after the page whose `next` is `None`.
    ///
    /// Each page runs in its own read transaction, so no reader connection stays checked out
    /// between pages. As a consequence, different pages can observe different snapshots of the
    /// database.
    pub(crate) fn pages<Q: Paginated>(
        &self,
        query: Q,
        start: Q::Cursor,
    ) -> impl Stream<Item = Result<Vec<Q::Item>>> + Send + use<Q> {
        let reader = self.reader.clone();
        let query = Arc::new(query);
        // The state holds where the next page starts, or `None` once the last page is read.
        futures::stream::try_unfold(Some(start), move |state: Option<Q::Cursor>| {
            let reader = reader.clone();
            let query = Arc::clone(&query);
            async move {
                let Some(next) = state else {
                    return Ok(None);
                };
                let page = reader
                    .read(std::any::type_name::<Q>(), move |tx| query.page(tx, &next))
                    .await?;
                if page.items.is_empty() {
                    return Ok(None);
                }
                Ok::<_, DatabaseError>(Some((page.items, page.next)))
            }
        })
    }

    /// Search for a [`BlockHeader`] from the database by its `block_num`.
    ///
    /// When `block_number` is [None], the latest block header is returned.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_block_header_by_block_num(
        &self,
        maybe_block_number: Option<ScopedBlockNum>,
    ) -> Result<Option<BlockHeader>> {
        self.reader
            .read("block headers by block number", move |tx| {
                queries::select_block_header_by_block_num(
                    tx,
                    maybe_block_number.map(|block_number| *block_number),
                )
            })
            .await
    }

    /// Selects the genesis block header for state initialization.
    pub(crate) async fn select_genesis_block_header(&self) -> Result<Option<BlockHeader>> {
        self.reader
            .read("genesis block header", |tx| {
                queries::select_block_header_by_block_num(tx, Some(BlockNumber::GENESIS))
            })
            .await
    }

    /// Search for a [`BlockHeader`] and its [`BlockSignatures`] from the database by its
    /// `block_num`.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_block_header_and_signatures_by_block_num(
        &self,
        block_number: ScopedBlockNum,
    ) -> Result<Option<(BlockHeader, BlockSignatures)>> {
        self.reader
            .read("block headers and signatures by block number", move |tx| {
                queries::select_block_header_and_signatures_by_block_num(tx, *block_number)
            })
            .await
    }

    /// Loads multiple block headers from the DB.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_block_headers(
        &self,
        blocks: impl Iterator<Item = ScopedBlockNum> + Send + 'static,
    ) -> Result<Vec<BlockHeader>> {
        self.reader
            .read("block headers from given block numbers", move |tx| {
                queries::select_block_headers(tx, blocks.map(|block| *block))
            })
            .await
    }

    /// Loads all the block headers from the DB.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_all_block_header_commitments(&self) -> Result<Vec<BlockHeaderCommitment>> {
        self.reader
            .read("all block headers", queries::select_all_block_header_commitments)
            .await
    }

    /// Loads public account details from the DB.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_account(&self, id: AccountId) -> Result<AccountInfo> {
        self.reader
            .read("Get account details", move |tx| queries::select_account(tx, id))
            .await
    }

    /// Returns the subset of the provided account IDs that classify as network accounts.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn filter_network_accounts(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<HashSet<AccountId>> {
        self.reader
            .read("Filter network accounts", move |tx| {
                queries::filter_network_accounts(tx, &account_ids)
            })
            .await
    }

    /// Queries the account code by its commitment hash.
    ///
    /// Returns `None` if no code exists with that commitment.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub async fn select_account_code_by_commitment(
        &self,
        code_commitment: Word,
    ) -> Result<Option<miden_protocol::account::AccountCode>> {
        self.reader
            .read("Get account code by commitment", move |tx| {
                queries::select_account_code_by_commitment(tx, code_commitment)?
                    .map(|bytes| {
                        miden_node_persistence::decode::<miden_protocol::account::AccountCode>(
                            &bytes,
                        )
                    })
                    .transpose()
                    .map_err(DatabaseError::from)
            })
            .await
    }

    /// Queries the account header and storage header for a specific account at a block.
    ///
    /// Returns both in a single query to avoid querying the database twice.
    /// Returns `None` if the account doesn't exist at that block.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub async fn select_account_header_with_storage_header_at_block(
        &self,
        account_id: AccountId,
        block_num: ScopedBlockNum,
    ) -> Result<Option<(AccountHeader, AccountStorageHeader)>> {
        self.reader
            .read("Get account header with storage header at block", move |tx| {
                queries::select_account_header_with_storage_header_at_block(
                    tx, account_id, *block_num,
                )
            })
            .await
    }

    /// Loads all the [`miden_protocol::note::Note`]s matching a certain [`NoteId`] from the
    /// database.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_notes_by_id(&self, note_ids: Vec<NoteId>) -> Result<Vec<NoteRecord>> {
        self.reader
            .read("note by id", move |tx| queries::select_notes_by_id(tx, note_ids.as_slice()))
            .await
    }

    /// Returns the requested note IDs that the database contains at or before `up_to_block`.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_existing_note_ids(
        &self,
        note_ids: Vec<NoteId>,
        up_to_block: ScopedBlockNum,
    ) -> Result<HashSet<NoteId>> {
        self.reader
            .read("existing note IDs", move |tx| {
                queries::select_existing_note_ids(tx, note_ids.as_slice(), *up_to_block)
            })
            .await
    }

    /// Loads inclusion proofs for notes matching the given note commitments that were committed at
    /// or before `up_to_block`.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn select_note_inclusion_proofs(
        &self,
        note_commitments: BTreeSet<Word>,
        up_to_block: ScopedBlockNum,
    ) -> Result<BTreeMap<NoteId, NoteInclusionProof>> {
        self.reader
            .read("block note inclusion proofs by commitment", move |tx| {
                queries::select_note_inclusion_proofs(tx, &note_commitments, *up_to_block)
            })
            .await
    }

    /// Inserts the data of a new block into the DB.
    ///
    /// The transaction is committed when this method returns. Synchronization with the in-memory
    /// trees is handled by the block writer task; see [`super::state::State::apply_block`].
    ///
    /// Account history is pruned in the same transaction against `prune_tip`: the effective tip
    /// for retention, which lags the actual tip while old snapshot generations are still pinned
    /// by readers (SQLite reads have no point-in-time protection, unlike the `RocksDB`-backed
    /// trees).
    ///
    /// Consumed note IDs omitted from transaction headers are resolved from
    /// `unresolved_note_nullifiers` on a best-effort basis. The returned mapping is used only for
    /// lifecycle events and never affects block application. `unresolved_note_nullifiers` is empty
    /// when neither INFO nor DEBUG lifecycle events are enabled.
    // TODO: This span is logged in a root span, we should connect it to the parent one.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the block and the state that the writer precomputed for it"
    )]
    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    pub(crate) async fn apply_block(
        &self,
        signed_block: SignedBlock,
        activated_protocol_config: Option<ProtocolConfig>,
        notes: Vec<(NoteRecord, Option<Nullifier>)>,
        precomputed_public_states: PrecomputedPublicAccountStates,
        new_account_ids: BTreeSet<AccountId>,
        unresolved_note_nullifiers: Vec<Nullifier>,
        prune_tip: BlockNumber,
    ) -> Result<BTreeMap<Nullifier, NoteId>> {
        self.writer
            .write::<_, DatabaseError, _>("apply block", move |tx| {
                if let Some(protocol_config) = activated_protocol_config.as_ref() {
                    queries::insert_protocol_config(
                        tx,
                        protocol_config,
                        signed_block.header().block_num(),
                    )?;
                }
                queries::apply_block(
                    tx,
                    &signed_block,
                    &notes,
                    &precomputed_public_states,
                    &new_account_ids,
                )?;
                queries::prune_history(tx, prune_tip)?;
                Ok(())
            })
            .await?;

        Ok(self.resolve_consumed_note_ids(unresolved_note_nullifiers).await)
    }

    /// Maps consumed nullifiers back to their note IDs for lifecycle events, on a best-effort
    /// basis.
    ///
    /// A failed lookup is logged and abandoned: the caller uses this only for reporting.
    async fn resolve_consumed_note_ids(
        &self,
        nullifiers: Vec<Nullifier>,
    ) -> BTreeMap<Nullifier, NoteId> {
        let mut resolved_note_ids = BTreeMap::new();
        for chunk in nullifiers.chunks(QueryParamNoteCommitmentLimit::LIMIT) {
            let chunk = chunk.to_vec();
            let count = chunk.len();
            let result = self
                .reader
                .read("resolve consumed note ids", move |tx| {
                    queries::select_note_ids_by_nullifier(tx, &chunk)
                })
                .await;

            match result {
                Ok(note_ids) => resolved_note_ids.extend(note_ids),
                Err(err) => {
                    warn!(
                        &err,
                        target: COMPONENT,
                        "Failed to resolve consumed note IDs for lifecycle events",
                        note.nullifier.count = count
                    );
                    break;
                },
            }
        }

        resolved_note_ids
    }

    /// Reconstructs storage map details from the database for a specific slot at a block.
    ///
    /// Used as fallback when `AccountStateForest` cache misses (historical or evicted queries).
    /// Rebuilds all entries by querying the DB and filtering to the specific slot.
    ///
    /// Returns:
    ///     - `::LimitExceeded` when too many entries are present
    ///     - `::AllEntries` if the size is less than or equal given `entries_limit`, if any
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub(crate) async fn reconstruct_storage_map_from_db(
        &self,
        account_id: AccountId,
        slot_name: miden_protocol::account::StorageSlotName,
        block_num: ScopedBlockNum,
        entries_limit: Option<usize>,
    ) -> Result<miden_node_proto::domain::account::AccountStorageMapDetails> {
        use miden_node_proto::domain::account::{AccountStorageMapDetails, StorageMapEntries};
        use miden_protocol::EMPTY_WORD;

        // TODO this remains expensive with a large history until we implement pruning for DB
        // columns
        let entries_limit = entries_limit.unwrap_or_else(default_storage_map_entries_limit);
        let query =
            queries::AccountStorageMapValuesPaged::new(account_id, block_num, entries_limit);

        let mut values = Vec::new();
        let mut pages = pin!(self.pages(query, BlockNumber::GENESIS));
        loop {
            match pages.try_next().await {
                Ok(Some(page)) => values.extend(page),
                Ok(None) => break,
                // A single block holds more entries than fit in a page, as with genesis accounts
                // that have large storage maps.
                Err(DatabaseError::BlockExceedsPageLimit { .. }) => {
                    return Ok(AccountStorageMapDetails::limit_exceeded(slot_name));
                },
                Err(err) => return Err(err),
            }
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

        let entries = latest_values.into_iter().collect::<Vec<_>>();
        Ok(AccountStorageMapDetails {
            slot_name,
            entries: StorageMapEntries::AllEntries(entries),
        })
    }

    /// Reconstructs the account vault from the database for a specific account at a block.
    ///
    /// Used as fallback when the `AccountStateForest` vault-key cache misses (historical or evicted
    /// queries). Returns the latest asset for each vault key at or before `block_num`.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub async fn select_vault_at_block(
        &self,
        account_id: AccountId,
        block_num: ScopedBlockNum,
    ) -> Result<Vec<Asset>, DatabaseError> {
        self.reader
            .read("select vault at block", move |tx| {
                queries::select_vault_at_block(tx, account_id, *block_num)
            })
            .await
    }

    /// Returns the script for a note by its root.
    pub async fn select_note_script_by_root(&self, root: Word) -> Result<Option<NoteScript>> {
        self.reader
            .read("note script by root", move |tx| queries::select_note_script_by_root(tx, root))
            .await
    }
}
