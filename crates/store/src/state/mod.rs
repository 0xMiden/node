//! Abstraction to synchronize state modifications.
//!
//! The [State] provides data access and modifications methods, its main purpose is to ensure that
//! data is atomically written, and that reads are consistent.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use miden_node_proto::domain::account::AccountInfo;
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::formatting::format_array;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageMapWitness, StorageSlotName};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::nullifier_tree::{NullifierTree, NullifierWitness};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::mmr::{MmrPeaks, MmrProof, PartialMmr};
use miden_protocol::crypto::merkle::smt::LargeSmt;
use miden_protocol::note::{NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::PartialBlockchain;
use tokio::sync::{RwLock, watch};
use tracing::{Span, info, instrument};

use crate::account_state_forest::{AccountStateForest, AccountStateForestBackend, WitnessError};
use crate::accounts::AccountTreeWithHistory;
use crate::blocks::BlockStore;
use crate::db::models::Page;
use crate::db::{Db, NoteRecord, NullifierInfo};
use crate::errors::{
    DatabaseError,
    GetBatchInputsError,
    GetBlockHeaderError,
    GetBlockInputsError,
    GetCurrentBlockchainDataError,
    StateInitializationError,
};
use crate::proven_tip::ProvenTipWriter;
use crate::{COMPONENT, DataDirectory, DatabaseOptions};

/// Number of recent committed blocks held in the in-memory cache for replica subscriptions.
const BLOCK_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(512).unwrap();

/// Number of recent block proofs held in the in-memory cache for replica subscriptions.
const PROOF_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(512).unwrap();

mod loader;
use loader::{
    ACCOUNT_STATE_FOREST_STORAGE_DIR,
    ACCOUNT_TREE_STORAGE_DIR,
    AccountForestLoader,
    NULLIFIER_TREE_STORAGE_DIR,
    SnapshotTreeStorage,
    TreeStorage,
    TreeStorageLoader,
    load_mmr,
    verify_account_state_forest_consistency,
    verify_tree_consistency,
};

mod replica;
pub use replica::{BlockCache, BlockNotification, ProofCache, ProofNotification};

mod account;

mod subscription;
pub use subscription::{
    BlockSubscriptionEvent,
    BlockSubscriptionStream,
    ProofSubscriptionEvent,
    ProofSubscriptionStream,
    StateSubscriptionError,
};

mod apply_block;
mod apply_proof;
mod bootstrap;
mod disk_monitor;
mod sync_state;
pub(crate) mod writer;
use writer::{BlockWriter, WriteHandle};

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

type BlockInputWitnesses = (
    BlockNumber,
    BTreeMap<AccountId, AccountWitness>,
    BTreeMap<Nullifier, NullifierWitness>,
    PartialMmr,
);

/// Immutable snapshot of in-memory tree state published after each committed block.
///
/// Backed by read-only snapshot storage so that any number of readers can access the data
/// concurrently without holding a lock.
pub(crate) struct InMemoryState {
    pub block_num: BlockNumber,
    pub nullifier_tree: NullifierTree<LargeSmt<SnapshotTreeStorage>>,
    pub account_tree: AccountTreeWithHistory<SnapshotTreeStorage>,
    pub blockchain: Blockchain,
}

// CHAIN STATE
// ================================================================================================

/// The rollup state.
pub struct State {
    /// Root directory containing the store's on-disk data.
    data_directory: PathBuf,

    /// The database which stores block headers, nullifiers, notes, and the latest states of
    /// accounts.
    db: Arc<Db>,

    /// The block store which stores full block contents for all blocks.
    block_store: Arc<BlockStore>,

    /// Atomically swappable pointer to the latest in-memory snapshot.
    ///
    /// Readers load the snapshot wait-free via `ArcSwap::load()`; the writer task atomically
    /// replaces the pointer after each committed block.
    in_memory: Arc<ArcSwap<InMemoryState>>,

    /// Handle for sending block-write requests to the [`BlockWriter`] task.
    write_handle: WriteHandle,

    /// Forest-related state `(SmtForest, storage_map_roots, vault_roots)` with its own lock.
    forest: Arc<RwLock<AccountStateForest<AccountStateForestBackend>>>,

    /// The latest proven-in-sequence block number, updated by the proof scheduler or `apply_proof`.
    proven_tip: ProvenTipWriter,

    /// Watch sender fired after each block is committed. Replicas subscribe via
    /// `subscribe_committed_tip()` to be woken when new blocks arrive.
    committed_tip_tx: Arc<watch::Sender<BlockNumber>>,

    /// FIFO cache of recent committed blocks for replica subscriptions.
    pub(crate) block_cache: BlockCache,

    /// FIFO cache of recent block proofs for replica subscriptions.
    pub(crate) proof_cache: ProofCache,
}

impl State {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Loads the state from the data directory.
    ///
    /// The loaded state owns all store data structures and exposes subscription methods for
    /// sequencer and replica tasks.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(
        data_path: &Path,
        storage_options: StorageOptions,
    ) -> Result<Self, StateInitializationError> {
        Self::load_with_database_options(data_path, storage_options, DatabaseOptions::default())
            .await
    }

    /// Loads the state from the data directory using explicit database options.
    ///
    /// The loaded state owns all store data structures and exposes subscription methods for
    /// sequencer and replica tasks.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load_with_database_options(
        data_path: &Path,
        storage_options: StorageOptions,
        database_options: DatabaseOptions,
    ) -> Result<Self, StateInitializationError> {
        let data_directory = DataDirectory::load(data_path.to_path_buf())
            .map_err(StateInitializationError::DataDirectoryLoadError)?;

        let block_store = Arc::new(
            BlockStore::load(data_directory.block_store_dir())
                .map_err(StateInitializationError::BlockStoreLoadError)?,
        );

        let database_filepath = data_directory.database_path();
        let mut db = Db::load_with_pool_size(
            database_filepath.clone(),
            database_options.connection_pool_size,
        )
        .await
        .map_err(StateInitializationError::DatabaseLoadError)?;

        let blockchain = load_mmr(&mut db).await?;
        let latest_block_num = blockchain.chain_tip().unwrap_or(BlockNumber::GENESIS);

        #[cfg(feature = "rocksdb")]
        let (account_storage_config, nullifier_storage_config, forest_storage_config) = (
            storage_options.account_tree.into(),
            storage_options.nullifier_tree.into(),
            storage_options.account_state_forest.into(),
        );
        #[cfg(not(feature = "rocksdb"))]
        let (account_storage_config, nullifier_storage_config, forest_storage_config) = {
            let _ = &storage_options;
            ((), (), ())
        };
        let account_storage =
            TreeStorage::create(data_path, &account_storage_config, ACCOUNT_TREE_STORAGE_DIR)?;
        let account_tree = account_storage.load_account_tree(&mut db).await?;

        let nullifier_storage =
            TreeStorage::create(data_path, &nullifier_storage_config, NULLIFIER_TREE_STORAGE_DIR)?;
        let nullifier_tree = nullifier_storage.load_nullifier_tree(&mut db).await?;

        verify_tree_consistency(account_tree.root(), nullifier_tree.root(), &mut db).await?;

        let account_tree = AccountTreeWithHistory::new(account_tree, latest_block_num);

        let forest_backend = AccountStateForestBackend::create(
            data_path,
            &forest_storage_config,
            ACCOUNT_STATE_FOREST_STORAGE_DIR,
        )?;
        let forest = forest_backend.load_account_state_forest(&mut db, latest_block_num).await?;
        verify_account_state_forest_consistency(&forest, &mut db).await?;

        let db = Arc::new(db);

        let proven_tip_init = block_store
            .load_proven_tip()
            .map_err(StateInitializationError::ProvenTipLoadError)?;
        let (proven_tip, _rx) = ProvenTipWriter::new(proven_tip_init);

        let (committed_tip_tx, _rx) = watch::channel(latest_block_num);
        let committed_tip_tx = Arc::new(committed_tip_tx);

        let forest = Arc::new(RwLock::new(forest));
        let block_cache = BlockCache::new(BLOCK_CACHE_CAPACITY);
        let proof_cache = ProofCache::new(PROOF_CACHE_CAPACITY);

        // Create the initial snapshot using reader views of the just-loaded trees.
        let initial_snapshot = Arc::new(InMemoryState {
            block_num: latest_block_num,
            nullifier_tree: nullifier_tree
                .reader()
                .map_err(|e| StateInitializationError::NullifierTreeIoError(e.to_string()))?,
            account_tree: account_tree.reader(),
            blockchain: blockchain.clone(),
        });
        let in_memory = Arc::new(ArcSwap::from(initial_snapshot));

        // Channel for write requests from State to BlockWriter.
        let (write_tx, write_rx) = tokio::sync::mpsc::channel(1);
        let write_handle = WriteHandle::new(write_tx);

        // Channel used by BlockWriter to signal critical errors; receiver is held for future use.
        let (termination_ask, _termination_rx) = tokio::sync::mpsc::channel(1);

        // Spawn the BlockWriter task.
        let block_writer = BlockWriter {
            db: Arc::clone(&db),
            block_store: Arc::clone(&block_store),
            in_memory: Arc::clone(&in_memory),
            forest: Arc::clone(&forest),
            committed_tip_tx: Arc::clone(&committed_tip_tx),
            block_cache: block_cache.clone(),
            termination_ask,
            rx: write_rx,
            nullifier_tree,
            account_tree,
            blockchain,
        };
        tokio::spawn(block_writer.run());

        Ok(Self {
            data_directory: data_path.to_path_buf(),
            db,
            block_store,
            in_memory,
            write_handle,
            forest,
            proven_tip,
            committed_tip_tx,
            block_cache,
            proof_cache,
        })
    }

    /// Returns a watch receiver that wakes every time a new block is committed.
    pub fn subscribe_committed_tip(&self) -> watch::Receiver<BlockNumber> {
        self.committed_tip_tx.subscribe()
    }

    /// Loads serialized block proving inputs from the block store.
    pub async fn load_proving_inputs(
        &self,
        block_num: BlockNumber,
    ) -> std::io::Result<Option<Vec<u8>>> {
        self.block_store.load_proving_inputs(block_num).await
    }

    /// Returns a watch receiver that wakes every time the proven-in-sequence tip advances.
    pub(crate) fn subscribe_proven_tip(&self) -> watch::Receiver<BlockNumber> {
        self.proven_tip.subscribe()
    }

    // SNAPSHOT HELPER
    // --------------------------------------------------------------------------------------------

    /// Returns the current in-memory snapshot (wait-free, no lock required).
    fn snapshot(&self) -> Arc<InMemoryState> {
        self.in_memory.load_full()
    }

    // HELPER FUNCTIONS TO AVOID BLOCKING CALLS IN ASYNC CONTEXT
    // --------------------------------------------------------------------------------------------

    /// Runs a synchronous operation over the current in-memory state snapshot on Tokio's blocking
    /// path.
    pub(crate) fn with_inner_read_blocking<R>(&self, f: impl FnOnce(&InMemoryState) -> R) -> R {
        let span = Span::current();
        tokio::task::block_in_place(|| {
            span.in_scope(|| {
                let snapshot = self.snapshot();
                f(&snapshot)
            })
        })
    }

    /// Runs a synchronous read-only operation over the account state forest on Tokio's blocking
    /// path.
    fn with_forest_read_blocking<R>(
        &self,
        f: impl FnOnce(&AccountStateForest<AccountStateForestBackend>) -> R,
    ) -> R {
        let span = Span::current();
        tokio::task::block_in_place(|| {
            span.in_scope(|| {
                let forest = self.forest.blocking_read();
                f(&forest)
            })
        })
    }

    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

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
        let block_header = self.db.select_block_header_by_block_num(block_num).await?;
        if let Some(header) = block_header {
            let mmr_proof = if include_mmr_proof {
                let snapshot = self.snapshot();
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

    /// Queries a list of notes from the database.
    pub async fn get_notes_by_id(
        &self,
        note_ids: Vec<NoteId>,
    ) -> Result<Vec<NoteRecord>, DatabaseError> {
        self.db.select_notes_by_id(note_ids).await
    }

    /// If the input block number is the current chain tip, `None` is returned. Otherwise, gets the
    /// current chain tip's block header with its corresponding MMR peaks.
    pub async fn get_current_blockchain_data(
        &self,
        block_num: Option<BlockNumber>,
    ) -> Result<Option<(BlockHeader, MmrPeaks)>, GetCurrentBlockchainDataError> {
        if let Some(number) = block_num
            && number == self.chain_tip(Finality::Committed)
        {
            return Ok(None);
        }

        // SAFETY: `select_block_header_by_block_num` will always return `Some(chain_tip_header)`
        // when `None` is passed
        let block_header: BlockHeader = self
            .db
            .select_block_header_by_block_num(None)
            .await
            .map_err(GetCurrentBlockchainDataError::ErrorRetrievingBlockHeader)?
            .unwrap();

        let snapshot = self.snapshot();
        let peaks = snapshot
            .blockchain
            .peaks_at(block_header.block_num())
            .map_err(GetCurrentBlockchainDataError::InvalidPeaks)?;

        Ok(Some((block_header, peaks)))
    }

    /// Fetches the inputs for a transaction batch from the database.
    pub async fn get_batch_inputs(
        &self,
        tx_reference_blocks: BTreeSet<BlockNumber>,
        unauthenticated_note_commitments: BTreeSet<Word>,
    ) -> Result<BatchInputs, GetBatchInputsError> {
        if tx_reference_blocks.is_empty() {
            return Err(GetBatchInputsError::TransactionBlockReferencesEmpty);
        }

        let note_proofs = self
            .db
            .select_note_inclusion_proofs(unauthenticated_note_commitments)
            .await
            .map_err(GetBatchInputsError::SelectNoteInclusionProofError)?;

        let note_blocks = note_proofs.values().map(|proof| proof.location().block_num());

        let mut blocks: BTreeSet<BlockNumber> = tx_reference_blocks;
        blocks.extend(note_blocks);

        let snapshot = self.snapshot();
        let (batch_reference_block, partial_mmr) = {
            let latest_block_num = snapshot.block_num;

            let highest_block_num =
                *blocks.last().expect("we should have checked for empty block references");
            if highest_block_num > latest_block_num {
                return Err(GetBatchInputsError::UnknownTransactionBlockReference {
                    highest_block_num,
                    latest_block_num,
                });
            }

            blocks.remove(&latest_block_num);

            // SAFETY: as in original code - latest block num exists in chain, all blocks < latest.
            let partial_mmr = snapshot
                .blockchain
                .partial_mmr_from_blocks(&blocks, latest_block_num)
                .expect("latest block num should exist and all blocks in set should be < than latest block");

            (latest_block_num, partial_mmr)
        };

        let mut headers = self
            .db
            .select_block_headers(blocks.into_iter().chain(std::iter::once(batch_reference_block)))
            .await
            .map_err(GetBatchInputsError::SelectBlockHeaderError)?;

        let header_index = headers
            .iter()
            .enumerate()
            .find_map(|(index, header)| {
                (header.block_num() == batch_reference_block).then_some(index)
            })
            .expect("DB should have returned the header of the batch reference block");

        let batch_reference_block_header = headers.swap_remove(header_index);

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
        let unauthenticated_note_proofs = self
            .db
            .select_note_inclusion_proofs(unauthenticated_note_commitments)
            .await
            .map_err(GetBlockInputsError::SelectNoteInclusionProofError)?;

        let note_proof_reference_blocks =
            unauthenticated_note_proofs.values().map(|proof| proof.location().block_num());

        let mut blocks = reference_blocks;
        blocks.extend(note_proof_reference_blocks);

        let (latest_block_number, account_witnesses, nullifier_witnesses, partial_mmr) =
            self.get_block_inputs_witnesses(&mut blocks, &account_ids, &nullifiers)?;

        let mut headers = self
            .db
            .select_block_headers(blocks.into_iter().chain(std::iter::once(latest_block_number)))
            .await
            .map_err(GetBlockInputsError::SelectBlockHeaderError)?;

        let latest_block_header_index = headers
            .iter()
            .enumerate()
            .find_map(|(index, header)| {
                (header.block_num() == latest_block_number).then_some(index)
            })
            .expect("DB should have returned the header of the latest block header");

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

    /// Get account and nullifier witnesses and [`PartialMmr`] for the given blocks.
    fn get_block_inputs_witnesses(
        &self,
        blocks: &mut BTreeSet<BlockNumber>,
        account_ids: &[AccountId],
        nullifiers: &[Nullifier],
    ) -> Result<BlockInputWitnesses, GetBlockInputsError> {
        let snapshot = self.snapshot();
        let span = Span::current();
        tokio::task::block_in_place(|| {
            span.in_scope(|| {
                let latest_block_number = snapshot.block_num;

                let highest_block_number = blocks.last().copied().unwrap_or(latest_block_number);
                if highest_block_number > latest_block_number {
                    return Err(GetBlockInputsError::UnknownBatchBlockReference {
                        highest_block_number,
                        latest_block_number,
                    });
                }

                blocks.remove(&latest_block_number);

                let partial_mmr =
                    snapshot.blockchain.partial_mmr_from_blocks(blocks, latest_block_number).expect(
                        "latest block num should exist and all blocks in set should be < than latest block",
                    );

                let account_witnesses = account_ids
                    .iter()
                    .copied()
                    .map(|account_id| (account_id, snapshot.account_tree.open_latest(account_id)))
                    .collect::<BTreeMap<AccountId, AccountWitness>>();

                let nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness> = nullifiers
                    .iter()
                    .copied()
                    .map(|nullifier| (nullifier, snapshot.nullifier_tree.open(&nullifier)))
                    .collect();

                Ok((latest_block_number, account_witnesses, nullifier_witnesses, partial_mmr))
            })
        })
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

        let snapshot = self.snapshot();
        let span = Span::current();
        let tree_inputs = tokio::task::block_in_place(|| {
            span.in_scope(|| {
                let account_commitment = snapshot.account_tree.get_latest_commitment(account_id);

                let new_account_id_prefix_is_unique = if account_commitment.is_empty() {
                    Some(
                        !snapshot
                            .account_tree
                            .contains_account_id_prefix_in_latest(account_id.prefix()),
                    )
                } else {
                    None
                };

                if let Some(false) = new_account_id_prefix_is_unique {
                    return Err(TransactionInputs {
                        new_account_id_prefix_is_unique,
                        ..Default::default()
                    });
                }

                let nullifiers = nullifiers
                    .iter()
                    .map(|nullifier| NullifierInfo {
                        nullifier: *nullifier,
                        block_num: snapshot
                            .nullifier_tree
                            .get_block_num(nullifier)
                            .unwrap_or_default(),
                    })
                    .collect();

                Ok((account_commitment, nullifiers, new_account_id_prefix_is_unique))
            })
        });
        let (account_commitment, nullifiers, new_account_id_prefix_is_unique) = match tree_inputs {
            Ok(inputs) => inputs,
            Err(inputs) => return Ok(inputs),
        };

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

    /// Filters `account_ids` down to the subset classified as network accounts.
    pub async fn filter_network_accounts(
        &self,
        account_ids: &[AccountId],
    ) -> Result<HashSet<AccountId>, DatabaseError> {
        self.db.select_network_accounts_subset(account_ids.to_vec()).await
    }

    /// Returns network account IDs within the specified block range.
    pub async fn get_all_network_accounts(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<AccountId>, BlockNumber), DatabaseError> {
        self.db.select_all_network_account_ids(block_range).await
    }

    /// Returns the effective chain tip for the given finality level.
    ///
    /// - [`Finality::Committed`]: returns the latest committed block number (from in-memory
    ///   snapshot, wait-free).
    /// - [`Finality::Proven`]: returns the latest proven-in-sequence block number (cached via watch
    ///   channel, updated by the proof scheduler).
    pub fn chain_tip(&self, finality: Finality) -> BlockNumber {
        match finality {
            Finality::Committed => self.in_memory.load().block_num,
            Finality::Proven => self.proven_tip.read(),
        }
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

    /// Returns the network notes for an account that are unconsumed by a specified block number.
    pub async fn get_unconsumed_network_notes_for_account(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        page: Page,
    ) -> Result<(Vec<NoteRecord>, Page), DatabaseError> {
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
        self.with_forest_read_blocking(|forest| {
            forest.get_vault_asset_witnesses(account_id, block_num, vault_keys)
        })
    }

    /// Returns a storage map witness for the specified account and storage entry at the block
    /// number.
    pub fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
        raw_key: StorageMapKey,
    ) -> Result<StorageMapWitness, WitnessError> {
        self.with_forest_read_blocking(|forest| {
            forest.get_storage_map_witness(account_id, slot_name, block_num, raw_key)
        })
    }
}
