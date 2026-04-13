//! State management for the Miden store.
//!
//! The [State] provides data access and modification methods. A single writer task, serialized by
//! a channel, applies block mutations. All reader-visible state (trees, blockchain MMR, forest) is
//! held in an [`Arc<InMemoryState>`] behind an [`ArcSwap`](arc_swap::ArcSwap), providing wait-free
//! reads with no lock contention.
//!
//! Readers obtain an `Arc<InMemoryState>` via [`State::snapshot()`] (wait-free, no locks).
//! The writer applies mutations to its own writable trees (owned directly, no locks), then builds
//! a new `InMemoryState` with snapshot-backed read-only copies and atomically swaps the pointer.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use miden_node_proto::BlockProofRequest;
use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountDetails,
    AccountInfo,
    AccountRequest,
    AccountResponse,
    AccountStorageDetails,
    AccountStorageMapDetails,
    AccountVaultDetails,
    SlotData,
    StorageMapRequest,
};
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::formatting::format_array;
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamStorageMapKeyTotalLimit};
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageMapWitness, StorageSlotName};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::nullifier_tree::{NullifierTree, NullifierWitness};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, Blockchain, SignedBlock};
use miden_protocol::crypto::merkle::mmr::{MmrPeaks, MmrProof, PartialMmr};
use miden_protocol::crypto::merkle::smt::{LargeSmt, SmtProof};
use miden_protocol::note::{NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::PartialBlockchain;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, instrument};

use crate::account_state_forest::{AccountStateForest, WitnessError};
use crate::accounts::AccountTreeWithHistory;
use crate::blocks::BlockStore;
use crate::db::models::Page;
use crate::db::{Db, NoteRecord, NullifierInfo};
use crate::errors::{
    ApplyBlockError,
    DatabaseError,
    GetAccountError,
    GetBatchInputsError,
    GetBlockHeaderError,
    GetBlockInputsError,
    GetCurrentBlockchainDataError,
    StateInitializationError,
};
use crate::proven_tip::{ProvenTipReader, ProvenTipWriter};
use crate::{COMPONENT, DataDirectory};

mod loader;

use loader::{
    ACCOUNT_TREE_STORAGE_DIR,
    NULLIFIER_TREE_STORAGE_DIR,
    SnapshotTreeStorage,
    StorageLoader,
    TreeStorage,
    load_mmr,
    load_smt_forest,
    verify_tree_consistency,
};

mod sync_state;
pub(crate) mod writer;

// FINALITY
// ================================================================================================

/// The finality level for chain tip queries.
#[derive(Debug, Clone, Copy)]
pub enum Finality {
    /// The latest committed (but not necessarily proven) block.
    Committed,
    /// The latest block that has been proven in an unbroken sequence from genesis.
    Proven,
}

// STRUCTURES
// ================================================================================================

#[derive(Debug, Default)]
pub struct TransactionInputs {
    pub account_commitment: Word,
    pub nullifiers: Vec<NullifierInfo>,
    pub found_unauthenticated_notes: HashSet<Word>,
    pub new_account_id_prefix_is_unique: Option<bool>,
}

// IN-MEMORY STATE
// ================================================================================================

/// A consistent, immutable snapshot of all in-memory state at a given block.
///
/// Held behind an [`ArcSwap`] in [`State`].
///
/// ## Performance
///
/// - **Readers** obtain an `Arc<InMemoryState>` via [`State::snapshot()`], which calls
///   `ArcSwap::load_full()` — a wait-free atomic refcount bump with no data cloning. The returned
///   `Arc` is a frozen view: even if the writer swaps in a new state, readers continue to see their
///   snapshot unchanged until they drop the `Arc`.
///
/// - **Writer** (once per block) deep-clones this struct via `InMemoryState::clone()` to produce a
///   mutable copy, applies mutations, and atomically swaps the pointer via `ArcSwap::store()`. This
///   is the only place where a deep clone occurs.
#[derive(Clone)]
pub(crate) struct InMemoryState {
    /// The committed block number for this snapshot.
    pub block_num: BlockNumber,
    /// Nullifier tree (read-only, snapshot-backed).
    pub nullifier_tree: NullifierTree<LargeSmt<SnapshotTreeStorage>>,
    /// Account tree with historical overlay support (read-only, snapshot-backed).
    pub account_tree: AccountTreeWithHistory<SnapshotTreeStorage>,
    /// Chain MMR (Merkle Mountain Range of block commitments).
    pub blockchain: Blockchain,
    /// Forest state for account storage maps and vault witnesses.
    pub forest: AccountStateForest,
}

// CHAIN STATE
// ================================================================================================

/// The rollup state.
///
/// A single writer task (serialized by a channel) mutates the state. All trees, the blockchain
/// MMR, and the forest are held in an `Arc<InMemoryState>` behind an [`ArcSwap`], providing
/// wait-free reads. The writer owns writable copies of the trees directly (passed as owned
/// values to [`writer::writer_loop`]) and creates snapshot-backed read-only copies for
/// `InMemoryState` after each block.
pub struct State {
    /// The database which stores block headers, nullifiers, notes, and the latest states of
    /// accounts.
    pub(super) db: Arc<Db>,

    /// The block store which stores full block contents for all blocks.
    pub(super) block_store: Arc<BlockStore>,

    /// Handle to the `RocksDB` database used for account tree storage.
    /// Used by the writer to create snapshot storage instances for `InMemoryState`.
    #[cfg(feature = "rocksdb")]
    pub(super) account_db: std::sync::Arc<miden_large_smt_backend_rocksdb::DB>,

    /// Handle to the `RocksDB` database used for nullifier tree storage.
    /// Used by the writer to create snapshot storage instances for `InMemoryState`.
    #[cfg(feature = "rocksdb")]
    pub(super) nullifier_db: std::sync::Arc<miden_large_smt_backend_rocksdb::DB>,

    /// All in-memory state held atomically behind an `ArcSwap`.
    ///
    /// Readers call `snapshot()` which returns `Arc<InMemoryState>` via a wait-free atomic
    /// refcount bump — no data cloning. The writer builds a new `InMemoryState` with
    /// snapshot-backed trees after each block and atomically swaps via `ArcSwap::store()`.
    pub(super) in_memory: ArcSwap<InMemoryState>,

    /// Channel to the single writer task.
    writer_tx: mpsc::Sender<writer::WriteRequest>,

    /// Request termination of the process due to a fatal internal state error.
    pub(super) termination_ask: tokio::sync::mpsc::Sender<ApplyBlockError>,

    /// The latest proven-in-sequence block number, updated by the proof scheduler.
    proven_tip: ProvenTipReader,
}

impl State {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Loads the state from the data directory.
    ///
    /// The returned `Arc<State>` is ready to use. The writer task is spawned internally and
    /// holds a clone of the `Arc`. Dropping all external clones and closing the writer channel
    /// will terminate the writer task.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(
        data_path: &Path,
        storage_options: StorageOptions,
        termination_ask: tokio::sync::mpsc::Sender<ApplyBlockError>,
    ) -> Result<(Arc<Self>, ProvenTipWriter), StateInitializationError> {
        let data_directory = DataDirectory::load(data_path.to_path_buf())
            .map_err(StateInitializationError::DataDirectoryLoadError)?;

        let block_store = Arc::new(
            BlockStore::load(data_directory.block_store_dir())
                .map_err(StateInitializationError::BlockStoreLoadError)?,
        );

        let database_filepath = data_directory.database_path();
        let mut db = Db::load(database_filepath.clone())
            .await
            .map_err(StateInitializationError::DatabaseLoadError)?;

        let blockchain = load_mmr(&mut db).await?;
        let latest_block_num = blockchain.chain_tip().unwrap_or(BlockNumber::GENESIS);

        let account_storage = TreeStorage::create(
            data_path,
            &storage_options.account_tree.into(),
            ACCOUNT_TREE_STORAGE_DIR,
        )?;

        // Grab the DB handle before loading (needed for creating snapshots).
        #[cfg(feature = "rocksdb")]
        let account_db = std::sync::Arc::clone(account_storage.db());

        let account_tree = account_storage.load_account_tree(&mut db).await?;

        let nullifier_storage = TreeStorage::create(
            data_path,
            &storage_options.nullifier_tree.into(),
            NULLIFIER_TREE_STORAGE_DIR,
        )?;

        // Grab the DB handle before loading (needed for creating snapshots).
        #[cfg(feature = "rocksdb")]
        let nullifier_db = std::sync::Arc::clone(nullifier_storage.db());

        let nullifier_tree = nullifier_storage.load_nullifier_tree(&mut db).await?;

        // Verify that tree roots match the expected roots from the database.
        verify_tree_consistency(account_tree.root(), nullifier_tree.root(), &mut db).await?;

        // Create the writable account tree with history (owned by the writer).
        let account_tree_with_history = AccountTreeWithHistory::new(account_tree, latest_block_num);

        // Create a snapshot-backed read-only account tree for InMemoryState.
        let snapshot_account_tree = {
            #[cfg(feature = "rocksdb")]
            {
                use miden_large_smt_backend_rocksdb::RocksDbSnapshotStorage;

                let snapshot_storage = RocksDbSnapshotStorage::new(Arc::clone(&account_db));
                let snapshot_smt = loader::load_smt(snapshot_storage)
                    .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))?;
                // SAFETY: The snapshot reads from the same DB that the writable tree
                // was just loaded and validated from. No need to re-validate.
                let snapshot_tree =
                    miden_protocol::block::account_tree::AccountTree::new_unchecked(snapshot_smt);
                AccountTreeWithHistory::from_parts(
                    snapshot_tree,
                    account_tree_with_history.block_number_latest(),
                    account_tree_with_history.overlays().clone(),
                )
            }
            #[cfg(not(feature = "rocksdb"))]
            {
                // In memory mode, the trees are the same type, just clone.
                account_tree_with_history.clone()
            }
        };

        // Create a snapshot-backed read-only nullifier tree for InMemoryState.
        let snapshot_nullifier_tree = {
            #[cfg(feature = "rocksdb")]
            {
                use miden_large_smt_backend_rocksdb::RocksDbSnapshotStorage;

                let snapshot_storage =
                    RocksDbSnapshotStorage::new(std::sync::Arc::clone(&nullifier_db));
                let snapshot_smt = loader::load_smt(snapshot_storage)
                    .map_err(|e| StateInitializationError::NullifierTreeIoError(e.to_string()))?;
                NullifierTree::new_unchecked(snapshot_smt)
            }
            #[cfg(not(feature = "rocksdb"))]
            {
                nullifier_tree.clone()
            }
        };

        let forest = load_smt_forest(&mut db, latest_block_num).await?;

        let db = Arc::new(db);

        // Initialize the proven tip from database.
        let proven_tip =
            db.proven_chain_tip().await.map_err(StateInitializationError::DatabaseError)?;
        let (proven_tip_writer, proven_tip) = ProvenTipWriter::new(proven_tip);

        // Create the writer channel. Buffer size of 1: only one block can be in flight.
        let (writer_tx, writer_rx) = mpsc::channel(1);

        let in_memory = ArcSwap::from_pointee(InMemoryState {
            block_num: latest_block_num,
            nullifier_tree: snapshot_nullifier_tree,
            account_tree: snapshot_account_tree,
            blockchain,
            forest,
        });

        let state = Arc::new(Self {
            db,
            block_store,
            #[cfg(feature = "rocksdb")]
            account_db,
            #[cfg(feature = "rocksdb")]
            nullifier_db,
            in_memory,
            writer_tx,
            termination_ask,
            proven_tip,
        });

        // Spawn the single writer task with owned writable trees.
        let writer_state = Arc::clone(&state);
        tokio::spawn(writer::writer_loop(
            writer_rx,
            writer_state,
            nullifier_tree,
            account_tree_with_history,
        ));

        Ok((state, proven_tip_writer))
    }

    /// Returns the database.
    pub(crate) fn db(&self) -> Arc<Db> {
        Arc::clone(&self.db)
    }

    /// Returns the block store.
    pub(crate) fn block_store(&self) -> Arc<BlockStore> {
        Arc::clone(&self.block_store)
    }

    // BLOCK APPLICATION
    // --------------------------------------------------------------------------------------------

    /// Apply changes of a new block to the DB and in-memory data structures.
    ///
    /// This sends the block to the single writer task via a channel and awaits the result.
    /// The writer task handles all validation, DB writes, and in-memory mutations.
    #[instrument(target = COMPONENT, skip_all, err, fields(block.number = signed_block.header().block_num().as_u32()))]
    pub async fn apply_block(
        &self,
        signed_block: SignedBlock,
        proving_inputs: Option<BlockProofRequest>,
    ) -> Result<(), ApplyBlockError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.writer_tx
            .send(writer::WriteRequest { signed_block, proving_inputs, result_tx })
            .await
            .map_err(|e| ApplyBlockError::WriterTaskSendFailed(Box::new(e)))?;
        result_rx.await?
    }

    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Takes a consistent snapshot of all in-memory state.
    ///
    /// Returns an `Arc<InMemoryState>` via a wait-free `ArcSwap::load_full()`. This performs
    /// only an atomic refcount increment — **no data is cloned**. No locks are acquired.
    ///
    /// The returned `Arc` is a frozen view: it keeps the snapshot alive for as long as needed,
    /// even if the writer swaps in a new state in the meantime. Readers holding the old `Arc`
    /// are completely unaffected by the swap.
    fn snapshot(&self) -> Arc<InMemoryState> {
        self.in_memory.load_full()
    }

    /// Returns the effective chain tip for the given finality level.
    ///
    /// - [`Finality::Committed`]: returns the latest committed block number from the in-memory
    ///   state snapshot (wait-free via `ArcSwap`).
    /// - [`Finality::Proven`]: returns the latest proven-in-sequence block number (cached via watch
    ///   channel, updated by the proof scheduler).
    pub fn chain_tip(&self, finality: Finality) -> BlockNumber {
        match finality {
            Finality::Committed => self.snapshot().block_num,
            Finality::Proven => self.proven_tip.read(),
        }
    }

    /// Queries a [BlockHeader] from the database, and returns it alongside its inclusion proof.
    ///
    /// If [None] is given as the value of `block_num`, the data for the latest [BlockHeader] is
    /// returned.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn get_block_header(
        &self,
        block_num: Option<BlockNumber>,
        include_mmr_proof: bool,
    ) -> Result<(Option<BlockHeader>, Option<MmrProof>), GetBlockHeaderError> {
        // Scope the DB query to the snapshot's block number to ensure consistency between
        // the block header (from SQLite) and the MMR proof (from the snapshot).
        let snapshot = self.snapshot();
        let block_num = block_num.unwrap_or(snapshot.block_num);
        if block_num > snapshot.block_num {
            return Err(GetBlockHeaderError::UnknownBlock(block_num));
        }
        let block_header = self.db.select_block_header_by_block_num(Some(block_num)).await?;
        if let Some(header) = block_header {
            let mmr_proof = if include_mmr_proof {
                let mmr_proof = snapshot.blockchain.open(header.block_num())?;
                Some(mmr_proof)
            } else {
                None
            };
            Ok((Some(header), mmr_proof))
        } else {
            Ok((None, None))
        }
    }

    /// Generates membership proofs for each one of the `nullifiers` against the latest nullifier
    /// tree.
    ///
    /// Note: these proofs are invalidated once the nullifier tree is modified, i.e. on a new block.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret)]
    pub async fn check_nullifiers(&self, nullifiers: &[Nullifier]) -> Vec<SmtProof> {
        let snapshot = self.snapshot();
        nullifiers
            .iter()
            .map(|n| snapshot.nullifier_tree.open(n))
            .map(NullifierWitness::into_proof)
            .collect()
    }

    /// Queries a list of notes from the database.
    ///
    /// If the provided list of [`NoteId`] given is empty or no note matches the provided
    /// [`NoteId`] an empty list is returned.
    pub async fn get_notes_by_id(
        &self,
        note_ids: Vec<NoteId>,
    ) -> Result<Vec<NoteRecord>, DatabaseError> {
        self.db.select_notes_by_id(note_ids).await
    }

    /// If the input block number is the current chain tip, `None` is returned.
    /// Otherwise, gets the current chain tip's block header with its corresponding MMR peaks.
    pub async fn get_current_blockchain_data(
        &self,
        block_num: Option<BlockNumber>,
    ) -> Result<Option<(BlockHeader, MmrPeaks)>, GetCurrentBlockchainDataError> {
        let snapshot = self.snapshot();
        if let Some(number) = block_num
            && number == snapshot.block_num
        {
            return Ok(None);
        }

        // Scope the DB query to the snapshot's block number to ensure consistency between
        // the block header (from SQLite) and the blockchain peaks (from the snapshot).
        let block_header: BlockHeader = self
            .db
            .select_block_header_by_block_num(Some(snapshot.block_num))
            .await
            .map_err(GetCurrentBlockchainDataError::ErrorRetrievingBlockHeader)?
            .expect("block header for snapshot block number must exist in DB");
        let peaks = snapshot
            .blockchain
            .peaks_at(block_header.block_num())
            .map_err(GetCurrentBlockchainDataError::InvalidPeaks)?;

        Ok(Some((block_header, peaks)))
    }

    /// Fetches the inputs for a transaction batch from the database.
    ///
    /// ## Inputs
    ///
    /// The function takes as input:
    /// - The tx reference blocks are the set of blocks referenced by transactions in the batch.
    /// - The unauthenticated note commitments are the set of commitments of unauthenticated notes
    ///   consumed by all transactions in the batch. For these notes, we attempt to find inclusion
    ///   proofs. Not all notes will exist in the DB necessarily, as some notes can be created and
    ///   consumed within the same batch.
    ///
    /// ## Outputs
    ///
    /// The function will return:
    /// - A block inclusion proof for all tx reference blocks and for all blocks which are
    ///   referenced by a note inclusion proof.
    /// - Note inclusion proofs for all notes that were found in the DB.
    /// - The block header that the batch should reference, i.e. the latest known block.
    pub async fn get_batch_inputs(
        &self,
        tx_reference_blocks: BTreeSet<BlockNumber>,
        unauthenticated_note_commitments: BTreeSet<Word>,
    ) -> Result<BatchInputs, GetBatchInputsError> {
        if tx_reference_blocks.is_empty() {
            return Err(GetBatchInputsError::TransactionBlockReferencesEmpty);
        }

        // First we grab note inclusion proofs for the known notes. These proofs only
        // prove that the note was included in a given block. We then also need to prove that
        // each of those blocks is included in the chain.
        let note_proofs = self
            .db
            .select_note_inclusion_proofs(unauthenticated_note_commitments)
            .await
            .map_err(GetBatchInputsError::SelectNoteInclusionProofError)?;

        // The set of blocks that the notes are included in.
        let note_blocks = note_proofs.values().map(|proof| proof.location().block_num());

        // Collect all blocks we need to query without duplicates, which is:
        // - all blocks for which we need to prove note inclusion.
        // - all blocks referenced by transactions in the batch.
        let mut blocks: BTreeSet<BlockNumber> = tx_reference_blocks;
        blocks.extend(note_blocks);

        let snapshot = self.snapshot();
        let latest_block_num = snapshot.block_num;

        let highest_block_num =
            *blocks.last().expect("we should have checked for empty block references");
        if highest_block_num > latest_block_num {
            return Err(GetBatchInputsError::UnknownTransactionBlockReference {
                highest_block_num,
                latest_block_num,
            });
        }

        // Remove the latest block from the to-be-tracked blocks as it will be the reference
        // block for the batch itself and thus added to the MMR within the batch kernel, so
        // there is no need to prove its inclusion.
        blocks.remove(&latest_block_num);

        // SAFETY:
        // - The latest block num was retrieved from the snapshot and the blockchain within the
        //   snapshot is guaranteed to be consistent with that block number.
        // - We have checked that no block number in the blocks set is greater than latest block
        //   number *and* latest block num was removed from the set.
        let partial_mmr =
            snapshot.blockchain.partial_mmr_from_blocks(&blocks, latest_block_num).expect(
                "latest block num should exist and all blocks in set should be < than latest block",
            );

        let batch_reference_block = latest_block_num;

        // Fetch the reference block of the batch as part of this query, so we can avoid looking it
        // up in a separate DB access.
        let mut headers = self
            .db
            .select_block_headers(blocks.into_iter().chain(std::iter::once(batch_reference_block)))
            .await
            .map_err(GetBatchInputsError::SelectBlockHeaderError)?;

        // Find and remove the batch reference block as we don't want to add it to the chain MMR.
        let header_index = headers
            .iter()
            .enumerate()
            .find_map(|(index, header)| {
                (header.block_num() == batch_reference_block).then_some(index)
            })
            .expect("DB should have returned the header of the batch reference block");

        // The order doesn't matter for PartialBlockchain::new, so swap remove is fine.
        let batch_reference_block_header = headers.swap_remove(header_index);

        // SAFETY: This should not error because:
        // - we're passing exactly the block headers that we've added to the partial MMR,
        // - so none of the block headers block numbers should exceed the chain length of the
        //   partial MMR,
        // - and we've added blocks to a BTreeSet, so there can be no duplicates.
        //
        // We construct headers and partial MMR in concert, so they are consistent. This is why we
        // can call the unchecked constructor.
        let partial_block_chain = PartialBlockchain::new_unchecked(partial_mmr, headers)
            .expect("partial mmr and block headers should be consistent");

        Ok(BatchInputs {
            batch_reference_block_header,
            note_proofs,
            partial_block_chain,
        })
    }

    /// Returns data needed by the block producer to construct and prove the next block.
    pub async fn get_block_inputs(
        &self,
        account_ids: Vec<AccountId>,
        nullifiers: Vec<Nullifier>,
        unauthenticated_note_commitments: BTreeSet<Word>,
        reference_blocks: BTreeSet<BlockNumber>,
    ) -> Result<BlockInputs, GetBlockInputsError> {
        // Get the note inclusion proofs from the DB.
        let unauthenticated_note_proofs = self
            .db
            .select_note_inclusion_proofs(unauthenticated_note_commitments)
            .await
            .map_err(GetBlockInputsError::SelectNoteInclusionProofError)?;

        // The set of blocks that the notes are included in.
        let note_proof_reference_blocks =
            unauthenticated_note_proofs.values().map(|proof| proof.location().block_num());

        // Collect all blocks we need to prove inclusion for, without duplicates.
        let mut blocks = reference_blocks;
        blocks.extend(note_proof_reference_blocks);

        let (latest_block_number, account_witnesses, nullifier_witnesses, partial_mmr) =
            self.get_block_inputs_witnesses(&mut blocks, &account_ids, &nullifiers)?;

        // Fetch the block headers for all blocks in the partial MMR plus the latest one which will
        // be used as the previous block header of the block being built.
        let mut headers = self
            .db
            .select_block_headers(blocks.into_iter().chain(std::iter::once(latest_block_number)))
            .await
            .map_err(GetBlockInputsError::SelectBlockHeaderError)?;

        // Find and remove the latest block as we must not add it to the chain MMR, since it is
        // not yet in the chain.
        let latest_block_header_index = headers
            .iter()
            .enumerate()
            .find_map(|(index, header)| {
                (header.block_num() == latest_block_number).then_some(index)
            })
            .expect("DB should have returned the header of the latest block header");

        // The order doesn't matter for PartialBlockchain::new, so swap remove is fine.
        let latest_block_header = headers.swap_remove(latest_block_header_index);

        let partial_block_chain = PartialBlockchain::new_unchecked(partial_mmr, headers)
            .expect("partial mmr and block headers should be consistent");

        Ok(BlockInputs::new(
            latest_block_header,
            partial_block_chain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        ))
    }

    /// Get account and nullifier witnesses for the requested account IDs and nullifiers as well as
    /// the [`PartialMmr`] for the given blocks. The MMR won't contain the latest block and its
    /// number is removed from `blocks` and returned separately.
    #[expect(clippy::type_complexity)]
    fn get_block_inputs_witnesses(
        &self,
        blocks: &mut BTreeSet<BlockNumber>,
        account_ids: &[AccountId],
        nullifiers: &[Nullifier],
    ) -> Result<
        (
            BlockNumber,
            BTreeMap<AccountId, AccountWitness>,
            BTreeMap<Nullifier, NullifierWitness>,
            PartialMmr,
        ),
        GetBlockInputsError,
    > {
        // Take a snapshot and extract everything we need from it.
        let snapshot = self.snapshot();
        let latest_block_number = snapshot.block_num;

        // If `blocks` is empty, use the latest block number which will never trigger the error.
        let highest_block_number = blocks.last().copied().unwrap_or(latest_block_number);
        if highest_block_number > latest_block_number {
            return Err(GetBlockInputsError::UnknownBatchBlockReference {
                highest_block_number,
                latest_block_number,
            });
        }

        // The latest block is not yet in the chain MMR, so we can't (and don't need to) prove
        // its inclusion in the chain.
        blocks.remove(&latest_block_number);

        let partial_mmr =
            snapshot.blockchain.partial_mmr_from_blocks(blocks, latest_block_number).expect(
                "latest block num should exist and all blocks in set should be < than latest block",
            );

        // Fetch witnesses for all accounts.
        let account_witnesses = account_ids
            .iter()
            .copied()
            .map(|account_id| (account_id, snapshot.account_tree.open_latest(account_id)))
            .collect::<BTreeMap<AccountId, AccountWitness>>();

        // Fetch witnesses for all nullifiers. We don't check whether the nullifiers are spent or
        // not as this is done as part of proposing the block.
        let nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness> = nullifiers
            .iter()
            .copied()
            .map(|nullifier| (nullifier, snapshot.nullifier_tree.open(&nullifier)))
            .collect();

        Ok((latest_block_number, account_witnesses, nullifier_witnesses, partial_mmr))
    }

    /// Returns data needed by the block producer to verify transactions validity.
    #[instrument(target = COMPONENT, skip_all, ret)]
    pub async fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        nullifiers: &[Nullifier],
        unauthenticated_note_commitments: Vec<Word>,
    ) -> Result<TransactionInputs, DatabaseError> {
        info!(target: COMPONENT, account_id = %account_id.to_string(), nullifiers = %format_array(nullifiers));

        // Take a snapshot and extract everything we need, then drop it so readers of newer
        // snapshots aren't held up by this Arc.
        let snapshot = self.snapshot();

        let account_commitment = snapshot.account_tree.get_latest_commitment(account_id);

        let new_account_id_prefix_is_unique = if account_commitment.is_empty() {
            Some(!snapshot.account_tree.contains_account_id_prefix_in_latest(account_id.prefix()))
        } else {
            None
        };

        // Non-unique account Id prefixes for new accounts are not allowed.
        if let Some(false) = new_account_id_prefix_is_unique {
            return Ok(TransactionInputs {
                new_account_id_prefix_is_unique,
                ..Default::default()
            });
        }

        let nullifiers = nullifiers
            .iter()
            .map(|nullifier| NullifierInfo {
                nullifier: *nullifier,
                block_num: snapshot.nullifier_tree.get_block_num(nullifier).unwrap_or_default(),
            })
            .collect();

        // Drop snapshot before the async DB call.
        drop(snapshot);

        let found_unauthenticated_notes = self
            .db
            .select_existing_note_commitments(unauthenticated_note_commitments)
            .await?;

        Ok(TransactionInputs {
            account_commitment,
            nullifiers,
            found_unauthenticated_notes,
            new_account_id_prefix_is_unique,
        })
    }

    /// Returns details for public (on-chain) account.
    pub async fn get_account_details(&self, id: AccountId) -> Result<AccountInfo, DatabaseError> {
        self.db.select_account(id).await
    }

    /// Returns details for public (on-chain) network accounts by full account ID.
    pub async fn get_network_account_details_by_id(
        &self,
        account_id: AccountId,
    ) -> Result<Option<AccountInfo>, DatabaseError> {
        self.db.select_network_account_by_id(account_id).await
    }

    /// Returns network account IDs within the specified block range (based on account creation
    /// block).
    pub async fn get_all_network_accounts(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<AccountId>, BlockNumber), DatabaseError> {
        self.db.select_all_network_account_ids(block_range).await
    }

    /// Returns an account witness and optionally account details at a specific block.
    ///
    /// The witness is a Merkle proof of inclusion in the account tree, proving the account's
    /// state commitment. If `details` is requested, the method also returns the account's code,
    /// vault assets, and storage data. Account details are only available for public accounts.
    ///
    /// If `block_num` is provided, returns the state at that historical block; otherwise, returns
    /// the latest state. Note that historical states are only available for recent blocks close
    /// to the chain tip.
    pub async fn get_account(
        &self,
        account_request: AccountRequest,
    ) -> Result<AccountResponse, GetAccountError> {
        let AccountRequest { block_num, account_id, details } = account_request;

        if details.is_some() && !account_id.has_public_state() {
            return Err(GetAccountError::AccountNotPublic(account_id));
        }

        let (block_num, witness) = self.get_account_witness(block_num, account_id)?;

        let details = if let Some(request) = details {
            Some(self.fetch_public_account_details(account_id, block_num, request).await?)
        } else {
            None
        };

        Ok(AccountResponse { block_num, witness, details })
    }

    /// Returns an account witness (Merkle proof of inclusion in the account tree).
    ///
    /// If `block_num` is provided, returns the witness at that historical block;
    /// otherwise, returns the witness at the latest block.
    fn get_account_witness(
        &self,
        block_num: Option<BlockNumber>,
        account_id: AccountId,
    ) -> Result<(BlockNumber, AccountWitness), GetAccountError> {
        let snapshot = self.snapshot();

        // Determine which block to query
        let (block_num, witness) = if let Some(requested_block) = block_num {
            if requested_block > snapshot.block_num {
                return Err(GetAccountError::UnknownBlock(requested_block));
            }
            // Historical query: use the account tree with history
            let witness =
                snapshot.account_tree.open_at(account_id, requested_block).ok_or_else(|| {
                    let latest_block = snapshot.account_tree.block_number_latest();
                    if requested_block > latest_block {
                        GetAccountError::UnknownBlock(requested_block)
                    } else {
                        GetAccountError::BlockPruned(requested_block)
                    }
                })?;
            (requested_block, witness)
        } else {
            // Latest query: use the latest state
            let block_num = snapshot.account_tree.block_number_latest();
            let witness = snapshot.account_tree.open_latest(account_id);
            (block_num, witness)
        };

        Ok((block_num, witness))
    }

    /// Fetches the account details (code, vault, storage) for a public account at the specified
    /// block.
    ///
    /// This method queries the database to fetch the account state and processes the detail
    /// request to return only the requested information.
    ///
    /// For specific key queries (`SlotData::MapKeys`), the forest is used to provide SMT proofs.
    /// Returns an error if the forest doesn't have data for the requested slot.
    /// All-entries queries (`SlotData::All`) use the forest to request all entries database.
    #[expect(clippy::too_many_lines)]
    async fn fetch_public_account_details(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        detail_request: AccountDetailRequest,
    ) -> Result<AccountDetails, GetAccountError> {
        let AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_requests,
        } = detail_request;

        if !account_id.has_public_state() {
            return Err(GetAccountError::AccountNotPublic(account_id));
        }

        // Validate block exists in the blockchain before querying the database.
        let snapshot = self.snapshot();
        if block_num > snapshot.block_num {
            return Err(GetAccountError::UnknownBlock(block_num));
        }

        // Query account header and storage header together in a single DB call
        let (account_header, storage_header) = self
            .db
            .select_account_header_with_storage_header_at_block(account_id, block_num)
            .await?
            .ok_or(GetAccountError::AccountNotFound(account_id, block_num))?;

        let account_code = match code_commitment {
            Some(commitment) if commitment == account_header.code_commitment() => None,
            Some(_) => {
                self.db
                    .select_account_code_by_commitment(account_header.code_commitment())
                    .await?
            },
            None => None,
        };

        let vault_details = match asset_vault_commitment {
            Some(commitment) if commitment == account_header.vault_root() => {
                AccountVaultDetails::empty()
            },
            Some(_) => {
                let vault_assets =
                    self.db.select_account_vault_at_block(account_id, block_num).await?;
                AccountVaultDetails::from_assets(vault_assets)
            },
            None => AccountVaultDetails::empty(),
        };

        let mut storage_map_details =
            Vec::<AccountStorageMapDetails>::with_capacity(storage_requests.len());
        let mut map_keys_requests = Vec::new();
        let mut all_entries_requests = Vec::new();
        let mut storage_request_slots = Vec::with_capacity(storage_requests.len());

        for (index, StorageMapRequest { slot_name, slot_data }) in
            storage_requests.into_iter().enumerate()
        {
            storage_request_slots.push(slot_name.clone());
            match slot_data {
                SlotData::MapKeys(keys) => {
                    map_keys_requests.push((index, slot_name, keys));
                },
                SlotData::All => {
                    all_entries_requests.push((index, slot_name));
                },
            }
        }

        let mut storage_map_details_by_index = vec![None; storage_request_slots.len()];

        if !map_keys_requests.is_empty() {
            for (index, slot_name, keys) in map_keys_requests {
                let details = snapshot
                    .forest
                    .get_storage_map_details_for_keys(
                        account_id,
                        slot_name.clone(),
                        block_num,
                        &keys,
                    )
                    .ok_or_else(|| DatabaseError::StorageRootNotFound {
                        account_id,
                        slot_name: slot_name.to_string(),
                        block_num,
                    })?
                    .map_err(DatabaseError::MerkleError)?;
                storage_map_details_by_index[index] = Some(details);
            }
        }

        // TODO parallelize the read requests
        for (index, slot_name) in all_entries_requests {
            let details = self
                .db
                .reconstruct_storage_map_from_db(
                    account_id,
                    slot_name.clone(),
                    block_num,
                    Some(
                        // TODO unify this with
                        // `AccountStorageMapDetails::MAX_RETURN_ENTRIES`
                        // and accumulated the limits
                        <QueryParamStorageMapKeyTotalLimit as QueryParamLimiter>::LIMIT,
                    ),
                )
                .await?;
            storage_map_details_by_index[index] = Some(details);
        }

        for (details, slot_name) in
            storage_map_details_by_index.into_iter().zip(storage_request_slots)
        {
            let details = details.ok_or_else(|| DatabaseError::StorageRootNotFound {
                account_id,
                slot_name: slot_name.to_string(),
                block_num,
            })?;
            storage_map_details.push(details);
        }

        Ok(AccountDetails {
            account_header,
            account_code,
            vault_details,
            storage_details: AccountStorageDetails {
                header: storage_header,
                map_details: storage_map_details,
            },
        })
    }

    /// Loads a block from the block store. Return `Ok(None)` if the block is not found.
    pub async fn load_block(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        if block_num > self.chain_tip(Finality::Committed) {
            return Ok(None);
        }
        self.block_store.load_block(block_num).await.map_err(Into::into)
    }

    /// Loads a block proof from the block store. Returns `Ok(None)` if the proof is not found.
    pub async fn load_proof(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        if block_num > self.chain_tip(Finality::Proven) {
            return Ok(None);
        }
        self.block_store.load_proof(block_num).await.map_err(Into::into)
    }

    /// Emits metrics for each database table's size.
    pub async fn analyze_table_sizes(&self) -> Result<(), DatabaseError> {
        self.db.analyze_table_sizes().await
    }

    /// Returns the network notes for an account that are unconsumed by a specified block number,
    /// along with the next pagination token.
    pub async fn get_unconsumed_network_notes_for_account(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        page: Page,
    ) -> Result<(Vec<NoteRecord>, Page), DatabaseError> {
        let snapshot = self.snapshot();
        if block_num > snapshot.block_num {
            return Err(DatabaseError::UnknownBlock(block_num));
        }
        self.db.select_unconsumed_network_notes(account_id, block_num, page).await
    }

    /// Returns the script for a note by its root.
    pub async fn get_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, DatabaseError> {
        self.db.select_note_script_by_root(root).await
    }

    /// Returns vault asset witnesses for the specified account and block number.
    pub fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> Result<Vec<AssetWitness>, WitnessError> {
        let snapshot = self.snapshot();
        if block_num > snapshot.block_num {
            return Err(WitnessError::UnknownBlock(block_num));
        }
        let witnesses =
            snapshot.forest.get_vault_asset_witnesses(account_id, block_num, vault_keys)?;
        Ok(witnesses)
    }

    /// Returns a storage map witness for the specified account and storage entry at the block
    /// number.
    ///
    /// Note that the `raw_key` is the raw, user-provided key that needs to be hashed in order to
    /// get the actual key into the storage map.
    pub fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
        raw_key: StorageMapKey,
    ) -> Result<StorageMapWitness, WitnessError> {
        let snapshot = self.snapshot();
        if block_num > snapshot.block_num {
            return Err(WitnessError::UnknownBlock(block_num));
        }
        let witness = snapshot
            .forest
            .get_storage_map_witness(account_id, slot_name, block_num, raw_key)?;
        Ok(witness)
    }
}
