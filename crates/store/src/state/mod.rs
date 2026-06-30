//! Abstraction to synchronize state modifications.
//!
//! The [State] provides data access and modifications methods, its main purpose is to ensure that
//! data is atomically written, and that reads are consistent.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use miden_node_proto::domain::batch::BatchInputs;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::formatting::format_array;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::nullifier_tree::{NullifierTree, NullifierWitness};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::mmr::{MmrProof, PartialMmr};
use miden_protocol::crypto::merkle::smt::{LargeSmt, SmtStorage};
use miden_protocol::note::{NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::PartialBlockchain;
use tokio::sync::{Mutex, RwLock, watch};
use tracing::{Instrument, Span, info, instrument};

use crate::account_state_forest::{AccountStateForest, AccountStateForestBackend};
use crate::accounts::AccountTreeWithHistory;
use crate::blocks::BlockStore;
use crate::db::{Db, NoteRecord, NullifierInfo};
use crate::errors::{
    DatabaseError,
    GetBatchInputsError,
    GetBlockHeaderError,
    GetBlockInputsError,
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
    BlockSubscriptionError,
    BlockSubscriptionEvent,
    BlockSubscriptionStream,
    DataError,
    ProofSubscriptionError,
    ProofSubscriptionEvent,
    ProofSubscriptionStream,
    SUBSCRIBER_CHANNEL_CAPACITY,
    StreamError,
    SubscriptionSource,
    SubscriptionStream,
    SubscriptionStreamError,
    run_stream,
};

mod apply_block;
mod apply_proof;
mod bootstrap;
mod disk_monitor;
mod sync_state;

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

/// Container for state that needs to be updated atomically.
struct InnerState<S>
where
    S: SmtStorage,
{
    nullifier_tree: NullifierTree<LargeSmt<S>>,
    blockchain: Blockchain,
    account_tree: AccountTreeWithHistory<S>,
}

impl<S: SmtStorage> InnerState<S> {
    /// Returns the latest block number.
    fn latest_block_num(&self) -> BlockNumber {
        self.blockchain
            .chain_tip()
            .expect("chain should always have at least the genesis block")
    }
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

    /// Read-write lock used to prevent writing to a structure while it is being used.
    ///
    /// The lock is writer-preferring, meaning the writer won't be starved.
    inner: RwLock<InnerState<TreeStorage>>,

    /// Forest-related state `(SmtForest, storage_map_roots, vault_roots)` with its own lock.
    forest: RwLock<AccountStateForest<AccountStateForestBackend>>,

    /// To allow readers to access the tree data while an update in being performed, and prevent
    /// TOCTOU issues, there must be no concurrent writers. This locks to serialize the writers.
    writer: Mutex<()>,

    /// The latest proven-in-sequence block number, updated by the proof scheduler or `apply_proof`.
    proven_tip: ProvenTipWriter,

    /// Watch sender fired after each block is committed. Replicas subscribe via
    /// `subscribe_committed_tip()` to be woken when new blocks arrive.
    committed_tip_tx: watch::Sender<BlockNumber>,

    /// FIFO cache of recent committed blocks for replica subscriptions. When a subscriber needs a
    /// block that has been evicted, it falls back to loading from the block store.
    pub(crate) block_cache: BlockCache,

    /// FIFO cache of recent block proofs for replica subscriptions. When a subscriber needs a proof
    /// that has been evicted, it falls back to loading from the block store.
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

        // Verify that tree roots match the expected roots from the database. This catches any
        // divergence between persistent storage and the database caused by corruption or incomplete
        // shutdown.
        verify_tree_consistency(account_tree.root(), nullifier_tree.root(), &mut db).await?;

        let account_tree = AccountTreeWithHistory::new(account_tree, latest_block_num);

        let forest_backend = AccountStateForestBackend::create(
            data_path,
            &forest_storage_config,
            ACCOUNT_STATE_FOREST_STORAGE_DIR,
        )?;
        let forest = forest_backend.load_account_state_forest(&mut db, latest_block_num).await?;
        verify_account_state_forest_consistency(&forest, &mut db).await?;

        let inner = RwLock::new(InnerState { nullifier_tree, blockchain, account_tree });

        let forest = RwLock::new(forest);
        let writer = Mutex::new(());
        let db = Arc::new(db);

        // Initialize the proven tip from the block store.
        let proven_tip_init = block_store
            .load_proven_tip()
            .map_err(StateInitializationError::ProvenTipLoadError)?;
        let (proven_tip, _rx) = ProvenTipWriter::new(proven_tip_init);

        // Committed-tip watch: fires after each successful apply_block.
        let (committed_tip_tx, _rx) = watch::channel(latest_block_num);

        Ok(Self {
            data_directory: data_path.to_path_buf(),
            db,
            block_store,
            inner,
            forest,
            writer,
            proven_tip,
            committed_tip_tx,
            block_cache: BlockCache::new(BLOCK_CACHE_CAPACITY),
            proof_cache: ProofCache::new(PROOF_CACHE_CAPACITY),
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

    // HELPER FUNCTIONS TO AVOID BLOCKING CALLS IN ASYNC CONTEXT
    // --------------------------------------------------------------------------------------------

    /// Runs a synchronous read-only operation over the inner state on Tokio's blocking path.
    ///
    /// The account and nullifier trees may be backed by `RocksDB`, so tree access must not run on
    /// an async worker thread directly. This helper preserves the current tracing span while
    /// moving the blocking lock acquisition and closure body into `block_in_place`.
    fn with_inner_read_blocking<R>(&self, f: impl FnOnce(&InnerState<TreeStorage>) -> R) -> R {
        let span = Span::current();
        tokio::task::block_in_place(|| {
            span.in_scope(|| {
                let inner = self.inner.blocking_read();
                f(&inner)
            })
        })
    }

    /// Runs a synchronous mutable operation over the inner state on Tokio's blocking path.
    ///
    /// See [`Self::with_inner_read_blocking`] for why this uses `block_in_place`.
    fn with_inner_write_blocking<R>(&self, f: impl FnOnce(&mut InnerState<TreeStorage>) -> R) -> R {
        let span = Span::current();
        tokio::task::block_in_place(|| {
            span.in_scope(|| {
                let mut inner = self.inner.blocking_write();
                f(&mut inner)
            })
        })
    }

    /// Runs a synchronous read-only operation over the account state forest on Tokio's blocking
    /// path.
    ///
    /// The forest may be backed by `RocksDB`, so accesses to the underlying `LargeSmtForest` must
    /// not run directly on an async worker thread.
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

    /// Runs a synchronous mutable operation over the account state forest on Tokio's blocking path.
    ///
    /// See [`Self::with_forest_read_blocking`] for why this uses `block_in_place`.
    fn with_forest_write_blocking<R>(
        &self,
        f: impl FnOnce(&mut AccountStateForest<AccountStateForestBackend>) -> R,
    ) -> R {
        let span = Span::current();
        tokio::task::block_in_place(|| {
            span.in_scope(|| {
                let mut forest = self.forest.blocking_write();
                f(&mut forest)
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
                let inner = self.inner.read().await;
                let mmr_proof = inner.blockchain.open(header.block_num())?;
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
    ///
    /// If the provided list of [`NoteId`] given is empty or no note matches the provided
    /// [`NoteId`] an empty list is returned.
    pub async fn get_notes_by_id(
        &self,
        note_ids: Vec<NoteId>,
    ) -> Result<Vec<NoteRecord>, DatabaseError> {
        self.db.select_notes_by_id(note_ids).await
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

        // First we grab note inclusion proofs for the known notes. These proofs only prove that the
        // note was included in a given block. We then also need to prove that each of those blocks
        // is included in the chain.
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

        // Scoped block to automatically drop the read lock guard as soon as we're done. We also
        // avoid accessing the db in the block as this would delay dropping the guard.
        let (batch_reference_block, partial_mmr) = {
            let inner_state = self.inner.read().await;

            let latest_block_num = inner_state.latest_block_num();

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
            // - The latest block num was retrieved from the inner blockchain from which we will
            //   also retrieve the proofs, so it is guaranteed to exist in that chain.
            // - We have checked that no block number in the blocks set is greater than latest block
            //   number *and* latest block num was removed from the set. Therefore only block
            //   numbers smaller than latest block num remain in the set. Therefore all the block
            //   numbers are guaranteed to exist in the chain state at latest block num.
            let partial_mmr = inner_state
                .blockchain
                .partial_mmr_from_blocks(&blocks, latest_block_num)
                .expect("latest block num should exist and all blocks in set should be < than latest block");

            (latest_block_num, partial_mmr)
        };

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
        // Get the note inclusion proofs from the DB. We do this first so we have to acquire the
        // lock to the state just once. There we need the reference blocks of the note proofs to get
        // their authentication paths in the chain MMR.
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

        // Find and remove the latest block as we must not add it to the chain MMR, since it is not
        // yet in the chain.
        let latest_block_header_index = headers
            .iter()
            .enumerate()
            .find_map(|(index, header)| {
                (header.block_num() == latest_block_number).then_some(index)
            })
            .expect("DB should have returned the header of the latest block header");

        // The order doesn't matter for PartialBlockchain::new, so swap remove is fine.
        let latest_block_header = headers.swap_remove(latest_block_header_index);

        // SAFETY: This should not error because:
        // - we're passing exactly the block headers that we've added to the partial MMR,
        // - so none of the block header's block numbers should exceed the chain length of the
        //   partial MMR,
        // - and we've added blocks to a BTreeSet, so there can be no duplicates.
        //
        // We construct headers and partial MMR in concert, so they are consistent. This is why we
        // can call the unchecked constructor.
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

    /// Get account and nullifier witnesses for the requested account IDs and nullifier as well as
    /// the [`PartialMmr`] for the given blocks. The MMR won't contain the latest block and its
    /// number is removed from `blocks` and returned separately.
    ///
    /// This method acquires the lock to the inner state and does not access the DB so we release
    /// the lock asap.
    fn get_block_inputs_witnesses(
        &self,
        blocks: &mut BTreeSet<BlockNumber>,
        account_ids: &[AccountId],
        nullifiers: &[Nullifier],
    ) -> Result<BlockInputWitnesses, GetBlockInputsError> {
        self.with_inner_read_blocking(|inner| {
            let latest_block_number = inner.latest_block_num();

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

            // Fetch the partial MMR at the state of the latest block with authentication paths for
            // the provided set of blocks.
            //
            // SAFETY:
            // - The latest block num was retrieved from the inner blockchain from which we will
            //   also retrieve the proofs, so it is guaranteed to exist in that chain.
            // - We have checked that no block number in the blocks set is greater than latest block
            //   number *and* latest block num was removed from the set. Therefore only block
            //   numbers smaller than latest block num remain in the set. Therefore all the block
            //   numbers are guaranteed to exist in the chain state at latest block num.
            let partial_mmr =
                inner.blockchain.partial_mmr_from_blocks(blocks, latest_block_number).expect(
                    "latest block num should exist and all blocks in set should be < than latest block",
                );

            // Fetch witnesses for all accounts.
            let account_witnesses = account_ids
                .iter()
                .copied()
                .map(|account_id| (account_id, inner.account_tree.open_latest(account_id)))
                .collect::<BTreeMap<AccountId, AccountWitness>>();

            // Fetch witnesses for all nullifiers. We don't check whether the nullifiers are spent
            // or not as this is done as part of proposing the block.
            let nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness> = nullifiers
                .iter()
                .copied()
                .map(|nullifier| (nullifier, inner.nullifier_tree.open(&nullifier)))
                .collect();

            Ok((latest_block_number, account_witnesses, nullifier_witnesses, partial_mmr))
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

        let tree_inputs = self.with_inner_read_blocking(|inner| {
            let account_commitment = inner.account_tree.get_latest_commitment(account_id);

            let new_account_id_prefix_is_unique = if account_commitment.is_empty() {
                Some(!inner.account_tree.contains_account_id_prefix_in_latest(account_id.prefix()))
            } else {
                None
            };

            // Non-unique account Id prefixes for new accounts are not allowed.
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
                    block_num: inner.nullifier_tree.get_block_num(nullifier).unwrap_or_default(),
                })
                .collect();

            Ok((account_commitment, nullifiers, new_account_id_prefix_is_unique))
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

    /// Filters `account_ids` down to the subset classified as network accounts.
    pub async fn filter_network_accounts(
        &self,
        account_ids: &[AccountId],
    ) -> Result<HashSet<AccountId>, DatabaseError> {
        self.db.select_network_accounts_subset(account_ids.to_vec()).await
    }

    /// Returns the effective chain tip for the given finality level.
    ///
    /// - [`Finality::Committed`]: returns the latest committed block number (from in-memory MMR).
    /// - [`Finality::Proven`]: returns the latest proven-in-sequence block number (cached via watch
    ///   channel, updated by the proof scheduler).
    pub async fn chain_tip(&self, finality: Finality) -> BlockNumber {
        match finality {
            Finality::Committed => self
                .inner
                .read()
                .instrument(tracing::info_span!("acquire_inner"))
                .await
                .latest_block_num(),
            Finality::Proven => self.proven_tip.read(),
        }
    }

    /// Loads a block from the block store. Return `Ok(None)` if the block is not found.
    pub async fn load_block(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        if block_num > self.chain_tip(Finality::Committed).await {
            return Ok(None);
        }
        self.block_store.load_block(block_num).await.map_err(Into::into)
    }

    /// Loads a block proof from the block store. Returns `Ok(None)` if the proof is not found.
    pub async fn load_proof(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        if block_num > self.chain_tip(Finality::Proven).await {
            return Ok(None);
        }
        self.block_store.load_proof(block_num).await.map_err(Into::into)
    }

    /// Returns the script for a note by its root.
    pub async fn get_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, DatabaseError> {
        self.db.select_note_script_by_root(root).await
    }
}
