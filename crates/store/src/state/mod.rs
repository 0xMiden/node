//! Abstraction to synchronize state modifications.
//!
//! The [State] provides data access and modifications methods, its main purpose is to ensure that
//! data is atomically written, and that reads are consistent.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

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
use miden_node_utils::ErrorReport;
use miden_node_utils::formatting::format_array;
use miden_protocol::Word;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{AccountId, StorageMapWitness, StorageSlotName};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::nullifier_tree::{NullifierTree, NullifierWitness};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, Blockchain, ProvenBlock};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrPeaks, MmrProof, PartialMmr};
use miden_protocol::crypto::merkle::smt::{LargeSmt, SmtProof, SmtStorage};
use miden_protocol::note::{NoteDetails, NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::{OutputNote, PartialBlockchain};
use miden_protocol::utils::Serializable;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{Instrument, info, info_span, instrument};

use crate::accounts::{AccountTreeWithHistory, HistoricalError};
use crate::blocks::BlockStore;
use crate::db::models::Page;
use crate::db::models::queries::StorageMapValuesPage;
use crate::db::{
    AccountVaultValue,
    Db,
    NoteRecord,
    NoteSyncUpdate,
    NullifierInfo,
    StateSyncUpdate,
};
use crate::errors::{
    ApplyBlockError,
    DatabaseError,
    GetBatchInputsError,
    GetBlockHeaderError,
    GetBlockInputsError,
    GetCurrentBlockchainDataError,
    InvalidBlockError,
    NoteSyncError,
    StateInitializationError,
    StateSyncError,
};
use crate::inner_forest::{InnerForest, WitnessError};
use crate::{COMPONENT, DataDirectory};

mod loader;

pub use loader::{
    ACCOUNT_TREE_STORAGE_DIR,
    NULLIFIER_TREE_STORAGE_DIR,
    StorageLoader,
    TreeStorage,
};
use loader::{load_mmr, load_smt_forest, verify_tree_consistency};

// STRUCTURES
// ================================================================================================

#[derive(Debug, Default)]
pub struct TransactionInputs {
    pub account_commitment: Word,
    pub nullifiers: Vec<NullifierInfo>,
    pub found_unauthenticated_notes: HashSet<Word>,
    pub new_account_id_prefix_is_unique: Option<bool>,
}

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
    forest: RwLock<InnerForest>,

    /// To allow readers to access the tree data while an update in being performed, and prevent
    /// TOCTOU issues, there must be no concurrent writers. This locks to serialize the writers.
    writer: Mutex<()>,

    /// Request termination of the process due to a fatal internal state error.
    termination_ask: tokio::sync::mpsc::Sender<ApplyBlockError>,
}

impl State {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Loads the state from the data directory.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(
        data_path: &Path,
        termination_ask: tokio::sync::mpsc::Sender<ApplyBlockError>,
    ) -> Result<Self, StateInitializationError> {
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

        let account_storage = TreeStorage::create(data_path, ACCOUNT_TREE_STORAGE_DIR)?;
        let account_tree = account_storage.load_account_tree(&mut db).await?;

        let nullifier_storage = TreeStorage::create(data_path, NULLIFIER_TREE_STORAGE_DIR)?;
        let nullifier_tree = nullifier_storage.load_nullifier_tree(&mut db).await?;

        // Verify that tree roots match the expected roots from the database.
        // This catches any divergence between persistent storage and the database caused by
        // corruption or incomplete shutdown.
        verify_tree_consistency(account_tree.root(), nullifier_tree.root(), &mut db).await?;

        let account_tree = AccountTreeWithHistory::new(account_tree, latest_block_num);

        let forest = load_smt_forest(&mut db, latest_block_num).await?;

        let inner = RwLock::new(InnerState { nullifier_tree, blockchain, account_tree });

        let forest = RwLock::new(forest);
        let writer = Mutex::new(());
        let db = Arc::new(db);

        Ok(Self {
            db,
            block_store,
            inner,
            forest,
            writer,
            termination_ask,
        })
    }

    // STATE MUTATOR
    // --------------------------------------------------------------------------------------------

    /// Apply changes of a new block to the DB and in-memory data structures.
    ///
    /// ## Note on state consistency
    ///
    /// The server contains in-memory representations of the existing trees, the in-memory
    /// representation must be kept consistent with the committed data, this is necessary so to
    /// provide consistent results for all endpoints. In order to achieve consistency, the
    /// following steps are used:
    ///
    /// - the request data is validated, prior to starting any modifications.
    /// - block is being saved into the store in parallel with updating the DB, but before
    ///   committing. This block is considered as candidate and not yet available for reading
    ///   because the latest block pointer is not updated yet.
    /// - a transaction is open in the DB and the writes are started.
    /// - while the transaction is not committed, concurrent reads are allowed, both the DB and the
    ///   in-memory representations, which are consistent at this stage.
    /// - prior to committing the changes to the DB, an exclusive lock to the in-memory data is
    ///   acquired, preventing concurrent reads to the in-memory data, since that will be
    ///   out-of-sync w.r.t. the DB.
    /// - the DB transaction is committed, and requests that read only from the DB can proceed to
    ///   use the fresh data.
    /// - the in-memory structures are updated, including the latest block pointer and the lock is
    ///   released.
    // TODO: This span is logged in a root span, we should connect it to the parent span.
    #[allow(clippy::too_many_lines)]
    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn apply_block(&self, block: ProvenBlock) -> Result<(), ApplyBlockError> {
        let _lock = self.writer.try_lock().map_err(|_| ApplyBlockError::ConcurrentWrite)?;

        let header = block.header();

        let tx_commitment = block.body().transactions().commitment();

        if header.tx_commitment() != tx_commitment {
            return Err(InvalidBlockError::InvalidBlockTxCommitment {
                expected: tx_commitment,
                actual: header.tx_commitment(),
            }
            .into());
        }

        let block_num = header.block_num();
        let block_commitment = header.commitment();

        // ensures the right block header is being processed
        let prev_block = self
            .db
            .select_block_header_by_block_num(None)
            .await?
            .ok_or(ApplyBlockError::DbBlockHeaderEmpty)?;

        let expected_block_num = prev_block.block_num().child();
        if block_num != expected_block_num {
            return Err(InvalidBlockError::NewBlockInvalidBlockNum {
                expected: expected_block_num,
                submitted: block_num,
            }
            .into());
        }
        if header.prev_block_commitment() != prev_block.commitment() {
            return Err(InvalidBlockError::NewBlockInvalidPrevCommitment.into());
        }

        let block_data = block.to_bytes();

        // Save the block to the block store. In a case of a rolled-back DB transaction, the
        // in-memory state will be unchanged, but the block might still be written into the
        // block store. Thus, such block should be considered as block candidates, but not
        // finalized blocks. So we should check for the latest block when getting block from
        // the store.
        let store = Arc::clone(&self.block_store);
        let block_save_task = tokio::spawn(
            async move { store.save_block(block_num, &block_data).await }.in_current_span(),
        );

        // scope to read in-memory data, compute mutations required for updating account
        // and nullifier trees, and validate the request
        let (
            nullifier_tree_old_root,
            nullifier_tree_update,
            account_tree_old_root,
            account_tree_update,
        ) = {
            let inner = self.inner.read().await;

            let _span = info_span!(target: COMPONENT, "update_in_memory_structs").entered();

            // nullifiers can be produced only once
            let duplicate_nullifiers: Vec<_> = block
                .body()
                .created_nullifiers()
                .iter()
                .filter(|&nullifier| inner.nullifier_tree.get_block_num(nullifier).is_some())
                .copied()
                .collect();
            if !duplicate_nullifiers.is_empty() {
                return Err(InvalidBlockError::DuplicatedNullifiers(duplicate_nullifiers).into());
            }

            // compute updates for the in-memory data structures

            // new_block.chain_root must be equal to the chain MMR root prior to the update
            let peaks = inner.blockchain.peaks();
            if peaks.hash_peaks() != header.chain_commitment() {
                return Err(InvalidBlockError::NewBlockInvalidChainCommitment.into());
            }

            // compute update for nullifier tree
            let nullifier_tree_update = inner
                .nullifier_tree
                .compute_mutations(
                    block
                        .body()
                        .created_nullifiers()
                        .iter()
                        .map(|nullifier| (*nullifier, block_num)),
                )
                .map_err(InvalidBlockError::NewBlockNullifierAlreadySpent)?;

            if nullifier_tree_update.as_mutation_set().root() != header.nullifier_root() {
                // We do our best here to notify the serve routine, if it doesn't care (dropped the
                // receiver) we can't do much.
                let _ = self.termination_ask.try_send(ApplyBlockError::InvalidBlockError(
                    InvalidBlockError::NewBlockInvalidNullifierRoot,
                ));
                return Err(InvalidBlockError::NewBlockInvalidNullifierRoot.into());
            }

            // compute update for account tree
            let account_tree_update = inner
                .account_tree
                .compute_mutations(
                    block
                        .body()
                        .updated_accounts()
                        .iter()
                        .map(|update| (update.account_id(), update.final_state_commitment())),
                )
                .map_err(|e| match e {
                    HistoricalError::AccountTreeError(err) => {
                        InvalidBlockError::NewBlockDuplicateAccountIdPrefix(err)
                    },
                    HistoricalError::MerkleError(_) => {
                        panic!("Unexpected MerkleError during account tree mutation computation")
                    },
                })?;

            if account_tree_update.as_mutation_set().root() != header.account_root() {
                let _ = self.termination_ask.try_send(ApplyBlockError::InvalidBlockError(
                    InvalidBlockError::NewBlockInvalidAccountRoot,
                ));
                return Err(InvalidBlockError::NewBlockInvalidAccountRoot.into());
            }

            (
                inner.nullifier_tree.root(),
                nullifier_tree_update,
                inner.account_tree.root_latest(),
                account_tree_update,
            )
        };

        // build note tree
        let note_tree = block.body().compute_block_note_tree();
        if note_tree.root() != header.note_root() {
            return Err(InvalidBlockError::NewBlockInvalidNoteRoot.into());
        }

        let notes = block
            .body()
            .output_notes()
            .map(|(note_index, note)| {
                let (details, nullifier) = match note {
                    OutputNote::Full(note) => {
                        (Some(NoteDetails::from(note)), Some(note.nullifier()))
                    },
                    OutputNote::Header(_) => (None, None),
                    note @ OutputNote::Partial(_) => {
                        return Err(InvalidBlockError::InvalidOutputNoteType(Box::new(
                            note.clone(),
                        )));
                    },
                };

                let inclusion_path = note_tree.open(note_index);

                let note_record = NoteRecord {
                    block_num,
                    note_index,
                    note_id: note.id().as_word(),
                    note_commitment: note.commitment(),
                    metadata: note.metadata().clone(),
                    details,
                    inclusion_path,
                };

                Ok((note_record, nullifier))
            })
            .collect::<Result<Vec<_>, InvalidBlockError>>()?;

        // Signals the transaction is ready to be committed, and the write lock can be acquired
        let (allow_acquire, acquired_allowed) = oneshot::channel::<()>();
        // Signals the write lock has been acquired, and the transaction can be committed
        let (inform_acquire_done, acquire_done) = oneshot::channel::<()>();

        // Extract public account updates with deltas before block is moved into async task.
        // Private accounts are filtered out since they don't expose their state changes.
        let account_deltas =
            Vec::from_iter(block.body().updated_accounts().iter().filter_map(|update| {
                match update.details() {
                    AccountUpdateDetails::Delta(delta) => Some(delta.clone()),
                    AccountUpdateDetails::Private => None,
                }
            }));

        // The DB and in-memory state updates need to be synchronized and are partially
        // overlapping. Namely, the DB transaction only proceeds after this task acquires the
        // in-memory write lock. This requires the DB update to run concurrently, so a new task is
        // spawned.
        let db = Arc::clone(&self.db);
        let db_update_task = tokio::spawn(
            async move { db.apply_block(allow_acquire, acquire_done, block, notes).await }
                .in_current_span(),
        );

        // Wait for the message from the DB update task, that we ready to commit the DB transaction
        acquired_allowed.await.map_err(ApplyBlockError::ClosedChannel)?;

        // Awaiting the block saving task to complete without errors
        block_save_task.await??;

        // Scope to update the in-memory data
        async move {
            // We need to hold the write lock here to prevent inconsistency between the in-memory
            // state and the DB state. Thus, we need to wait for the DB update task to complete
            // successfully.
            let mut inner = self.inner.write().await;

            // We need to check that neither the nullifier tree nor the account tree have changed
            // while we were waiting for the DB preparation task to complete. If either of them
            // did change, we do not proceed with in-memory and database updates, since it may
            // lead to an inconsistent state.
            if inner.nullifier_tree.root() != nullifier_tree_old_root
                || inner.account_tree.root_latest() != account_tree_old_root
            {
                return Err(ApplyBlockError::ConcurrentWrite);
            }

            // Notify the DB update task that the write lock has been acquired, so it can commit
            // the DB transaction
            inform_acquire_done
                .send(())
                .map_err(|_| ApplyBlockError::DbUpdateTaskFailed("Receiver was dropped".into()))?;

            // TODO: shutdown #91
            // Await for successful commit of the DB transaction. If the commit fails, we mustn't
            // change in-memory state, so we return a block applying error and don't proceed with
            // in-memory updates.
            db_update_task
                .await?
                .map_err(|err| ApplyBlockError::DbUpdateTaskFailed(err.as_report()))?;

            // Update the in-memory data structures after successful commit of the DB transaction
            inner
                .nullifier_tree
                .apply_mutations(nullifier_tree_update)
                .expect("Unreachable: old nullifier tree root must be checked before this step");
            inner
                .account_tree
                .apply_mutations(account_tree_update)
                .expect("Unreachable: old account tree root must be checked before this step");
            inner.blockchain.push(block_commitment);

            Ok(())
        }
        .in_current_span()
        .await?;

        self.forest.write().await.apply_block_updates(block_num, account_deltas)?;

        info!(%block_commitment, block_num = block_num.as_u32(), COMPONENT, "apply_block successful");

        Ok(())
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

    pub async fn sync_nullifiers(
        &self,
        prefix_len: u32,
        nullifier_prefixes: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<NullifierInfo>, BlockNumber), DatabaseError> {
        self.db
            .select_nullifiers_by_prefix(prefix_len, nullifier_prefixes, block_range)
            .await
    }

    /// Generates membership proofs for each one of the `nullifiers` against the latest nullifier
    /// tree.
    ///
    /// Note: these proofs are invalidated once the nullifier tree is modified, i.e. on a new block.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret)]
    pub async fn check_nullifiers(&self, nullifiers: &[Nullifier]) -> Vec<SmtProof> {
        let inner = self.inner.read().await;
        nullifiers
            .iter()
            .map(|n| inner.nullifier_tree.open(n))
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
        let blockchain = &self.inner.read().await.blockchain;
        if let Some(number) = block_num
            && number == self.latest_block_num().await
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
        let peaks = blockchain
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

        // Scoped block to automatically drop the read lock guard as soon as we're done.
        // We also avoid accessing the db in the block as this would delay dropping the guard.
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

    /// Loads data to synchronize a client.
    ///
    /// The client's request contains a list of note tags, this method will return the first
    /// block with a matching tag, or the chain tip. All the other values are filtered based on this
    /// block range.
    ///
    /// # Arguments
    ///
    /// - `block_num`: The last block *known* by the client, updates start from the next block.
    /// - `account_ids`: Include the account's commitment if their _last change_ was in the result's
    ///   block range.
    /// - `note_tags`: The tags the client is interested in, result is restricted to the first block
    ///   with any matches tags.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_state(
        &self,
        block_num: BlockNumber,
        account_ids: Vec<AccountId>,
        note_tags: Vec<u32>,
    ) -> Result<(StateSyncUpdate, MmrDelta), StateSyncError> {
        let inner = self.inner.read().await;

        let state_sync = self.db.get_state_sync(block_num, account_ids, note_tags).await?;

        let delta = if block_num == state_sync.block_header.block_num() {
            // The client is in sync with the chain tip.
            MmrDelta {
                forest: Forest::new(block_num.as_usize()),
                data: vec![],
            }
        } else {
            // Important notes about the boundary conditions:
            //
            // - The Mmr forest is 1-indexed whereas the block number is 0-indexed. The Mmr root
            // contained in the block header always lag behind by one block, this is because the Mmr
            // leaves are hashes of block headers, and we can't have self-referential hashes. These
            // two points cancel out and don't require adjusting.
            // - Mmr::get_delta is inclusive, whereas the sync_state request block_num is defined to
            //   be
            // exclusive, so the from_forest has to be adjusted with a +1
            let from_forest = (block_num + 1).as_usize();
            let to_forest = state_sync.block_header.block_num().as_usize();
            inner
                .blockchain
                .as_mmr()
                .get_delta(Forest::new(from_forest), Forest::new(to_forest))
                .map_err(StateSyncError::FailedToBuildMmrDelta)?
        };

        Ok((state_sync, delta))
    }

    /// Loads data to synchronize a client's notes.
    ///
    /// The client's request contains a list of tags, this method will return the first
    /// block with a matching tag, or the chain tip. All the other values are filter based on this
    /// block range.
    ///
    /// # Arguments
    ///
    /// - `note_tags`: The tags the client is interested in, resulting notes are restricted to the
    ///   first block containing a matching note.
    /// - `block_range`: The range of blocks from which to synchronize notes.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_notes(
        &self,
        note_tags: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(NoteSyncUpdate, MmrProof, BlockNumber), NoteSyncError> {
        let inner = self.inner.read().await;

        let (note_sync, last_included_block) =
            self.db.get_note_sync(block_range, note_tags).await?;

        let mmr_proof = inner.blockchain.open(note_sync.block_header.block_num())?;

        Ok((note_sync, mmr_proof, last_included_block))
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
        // We do this first so we have to acquire the lock to the state just once. There we need the
        // reference blocks of the note proofs to get their authentication paths in the chain MMR.
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
            self.get_block_inputs_witnesses(&mut blocks, account_ids, nullifiers).await?;

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
    async fn get_block_inputs_witnesses(
        &self,
        blocks: &mut BTreeSet<BlockNumber>,
        account_ids: Vec<AccountId>,
        nullifiers: Vec<Nullifier>,
    ) -> Result<
        (
            BlockNumber,
            BTreeMap<AccountId, AccountWitness>,
            BTreeMap<Nullifier, NullifierWitness>,
            PartialMmr,
        ),
        GetBlockInputsError,
    > {
        let inner = self.inner.read().await;

        let latest_block_number = inner.latest_block_num();

        // If `blocks` is empty, use the latest block number which will never trigger the error.
        let highest_block_number = blocks.last().copied().unwrap_or(latest_block_number);
        if highest_block_number > latest_block_number {
            return Err(GetBlockInputsError::UnknownBatchBlockReference {
                highest_block_number,
                latest_block_number,
            });
        }

        // The latest block is not yet in the chain MMR, so we can't (and don't need to) prove its
        // inclusion in the chain.
        blocks.remove(&latest_block_number);

        // Fetch the partial MMR at the state of the latest block with authentication paths for the
        // provided set of blocks.
        //
        // SAFETY:
        // - The latest block num was retrieved from the inner blockchain from which we will also
        //   retrieve the proofs, so it is guaranteed to exist in that chain.
        // - We have checked that no block number in the blocks set is greater than latest block
        //   number *and* latest block num was removed from the set. Therefore only block numbers
        //   smaller than latest block num remain in the set. Therefore all the block numbers are
        //   guaranteed to exist in the chain state at latest block num.
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

        // Fetch witnesses for all nullifiers. We don't check whether the nullifiers are spent or
        // not as this is done as part of proposing the block.
        let nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness> = nullifiers
            .iter()
            .copied()
            .map(|nullifier| (nullifier, inner.nullifier_tree.open(&nullifier)))
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

        let inner = self.inner.read().await;

        let account_commitment = inner.account_tree.get_latest_commitment(account_id);

        let new_account_id_prefix_is_unique = if account_commitment.is_empty() {
            Some(!inner.account_tree.contains_account_id_prefix_in_latest(account_id.prefix()))
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
                block_num: inner.nullifier_tree.get_block_num(nullifier).unwrap_or_default(),
            })
            .collect();

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
    ///
    /// The function may return fewer accounts than exist in the range if the result would exceed
    /// `MAX_RESPONSE_PAYLOAD_BYTES / AccountId::SERIALIZED_SIZE` rows. In this case, the result is
    /// truncated at a block boundary to ensure all accounts from included blocks are returned.
    ///
    /// The response includes the last block number that was fully included in the result.
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
    ) -> Result<AccountResponse, DatabaseError> {
        let AccountRequest { block_num, account_id, details } = account_request;

        if details.is_some() && !account_id.has_public_state() {
            return Err(DatabaseError::AccountNotPublic(account_id));
        }

        let (block_num, witness) = self.get_account_witness(block_num, account_id).await?;

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
    async fn get_account_witness(
        &self,
        block_num: Option<BlockNumber>,
        account_id: AccountId,
    ) -> Result<(BlockNumber, AccountWitness), DatabaseError> {
        let inner_state = self.inner.read().await;

        // Determine which block to query
        let (block_num, witness) = if let Some(requested_block) = block_num {
            // Historical query: use the account tree with history
            let witness = inner_state
                .account_tree
                .open_at(account_id, requested_block)
                .ok_or_else(|| DatabaseError::HistoricalBlockNotAvailable {
                    block_num: requested_block,
                    reason: "Block is either in the future or has been pruned from history"
                        .to_string(),
                })?;
            (requested_block, witness)
        } else {
            // Latest query: use the latest state
            let block_num = inner_state.account_tree.block_number_latest();
            let witness = inner_state.account_tree.open_latest(account_id);
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
    /// All-entries queries (`SlotData::All`) use the forest to return all entries.
    async fn fetch_public_account_details(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        detail_request: AccountDetailRequest,
    ) -> Result<AccountDetails, DatabaseError> {
        let AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_requests,
        } = detail_request;

        if !account_id.has_public_state() {
            return Err(DatabaseError::AccountNotPublic(account_id));
        }

        // Validate block exists in the blockchain before querying the database
        self.validate_block_exists(block_num).await?;

        // Query account header and storage header together in a single DB call
        let (account_header, storage_header) = self
            .db
            .select_account_header_with_storage_header_at_block(account_id, block_num)
            .await?
            .ok_or(DatabaseError::AccountAtBlockHeightNotFoundInDb(account_id, block_num))?;

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

        // Use forest for storage map queries
        let forest_guard = self.forest.read().await;

        for StorageMapRequest { slot_name, slot_data } in storage_requests {
            let details = match &slot_data {
                SlotData::MapKeys(keys) => forest_guard
                    .open_storage_map(account_id, slot_name.clone(), block_num, keys)
                    .ok_or_else(|| DatabaseError::StorageRootNotFound {
                        account_id,
                        slot_name: slot_name.to_string(),
                        block_num,
                    })?
                    .map_err(DatabaseError::MerkleError)?,
                SlotData::All => forest_guard
                    .storage_map_entries(account_id, slot_name.clone(), block_num)
                    .ok_or_else(|| DatabaseError::StorageRootNotFound {
                        account_id,
                        slot_name: slot_name.to_string(),
                        block_num,
                    })?,
            };

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

    /// Returns storage map values for syncing within a block range.
    pub(crate) async fn get_storage_map_sync_values(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<StorageMapValuesPage, DatabaseError> {
        self.db.select_storage_map_sync_values(account_id, block_range).await
    }

    /// Loads a block from the block store. Return `Ok(None)` if the block is not found.
    pub async fn load_block(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        if block_num > self.latest_block_num().await {
            return Ok(None);
        }
        self.block_store.load_block(block_num).await.map_err(Into::into)
    }

    /// Returns the latest block number.
    pub async fn latest_block_num(&self) -> BlockNumber {
        self.inner.read().await.latest_block_num()
    }

    /// Validates that a block exists in the blockchain
    ///
    /// # Attention
    ///
    /// Acquires a *read lock** on `self.inner`.
    ///
    /// # Errors
    ///
    /// Returns `DatabaseError::BlockNotFound` if the block doesn't exist in the blockchain.
    async fn validate_block_exists(&self, block_num: BlockNumber) -> Result<(), DatabaseError> {
        let inner = self.inner.read().await;
        let latest_block_num = inner.latest_block_num();

        if block_num > latest_block_num {
            return Err(DatabaseError::BlockNotFound(block_num));
        }

        Ok(())
    }

    /// Emits metrics for each database table's size.
    pub async fn analyze_table_sizes(&self) -> Result<(), DatabaseError> {
        self.db.analyze_table_sizes().await
    }

    /// Returns account vault updates for specified account within a block range.
    pub async fn sync_account_vault(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<AccountVaultValue>), DatabaseError> {
        self.db.get_account_vault_sync(account_id, block_range).await
    }
    /// Returns the network notes for an account that are unconsumed by a specified block number,
    /// along with the next pagination token.
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

    /// Returns the complete transaction records for the specified accounts within the specified
    /// block range, including state commitments and note IDs.
    pub async fn sync_transactions(
        &self,
        account_ids: Vec<AccountId>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<crate::db::TransactionRecord>), DatabaseError> {
        self.db.select_transactions_records(account_ids, block_range).await
    }

    /// Returns vault asset witnesses for the specified account and block number.
    pub async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> Result<Vec<AssetWitness>, WitnessError> {
        let witnesses = self
            .forest
            .read()
            .await
            .get_vault_asset_witnesses(account_id, block_num, vault_keys)?;
        Ok(witnesses)
    }

    /// Returns a storage map witness for the specified account and storage entry at the block
    /// number.
    ///
    /// Note that the `raw_key` is the raw, user-provided key that needs to be hashed in order to
    /// get the actual key into the storage map.
    pub async fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
        raw_key: Word,
    ) -> Result<StorageMapWitness, WitnessError> {
        let witness = self
            .forest
            .read()
            .await
            .get_storage_map_witness(account_id, slot_name, block_num, raw_key)?;
        Ok(witness)
    }
}
