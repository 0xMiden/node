use std::sync::Arc;

use arc_swap::ArcSwap;
use miden_node_proto::BlockProofRequest;
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::account::delta::{AccountDelta, AccountUpdateDetails};
use miden_protocol::block::account_tree::AccountMutationSet;
use miden_protocol::block::nullifier_tree::{NullifierMutationSet, NullifierTree};
use miden_protocol::block::{BlockBody, BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::crypto::merkle::smt::LargeSmt;
use miden_protocol::note::NoteDetails;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, instrument};

use crate::accounts::AccountTreeWithHistory;
use crate::blocks::BlockStore;
use crate::db::{Db, NoteRecord};
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::InMemoryState;
use crate::state::loader::{SnapshotTreeStorage, TreeStorage};
use crate::{COMPONENT, HistoricalError};

// WRITE HANDLE
// ================================================================================================

/// Handle for submitting blocks to the writer loop.
///
/// This is intentionally separated from [`super::State`] to avoid a circular reference: the writer
/// loop must not hold a reference back to the sender's owner.
#[derive(Clone)]
pub struct WriteHandle {
    tx: mpsc::Sender<WriteRequest>,
}

impl WriteHandle {
    pub(crate) fn new(tx: mpsc::Sender<WriteRequest>) -> Self {
        Self { tx }
    }

    /// Sends a block to the writer loop and awaits the result.
    pub async fn apply_block(
        &self,
        signed_block: SignedBlock,
        proving_inputs: Option<BlockProofRequest>,
    ) -> Result<(), ApplyBlockError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.tx
            .send(WriteRequest { signed_block, proving_inputs, result_tx })
            .await
            .map_err(|e| ApplyBlockError::WriterTaskSendFailed(Box::new(e)))?;
        result_rx.await?
    }
}

// BLOCK WRITER
// ================================================================================================

/// Single writer task that serializes all block mutations.
///
/// Owns the channel receiver and writable trees, and holds shared references to the database,
/// block store, and in-memory state. Deliberately does not reference `State` to avoid circular
/// references — the channel sender lives in [`WriteHandle`], which is independent of `State`.
pub(crate) struct BlockWriter {
    /// Channel receiver for incoming block write requests.
    pub rx: mpsc::Receiver<WriteRequest>,

    /// Writable account tree with historical overlays, owned exclusively by the writer.
    pub account_tree: AccountTreeWithHistory<TreeStorage>,
    /// Writable nullifier tree, owned exclusively by the writer.
    pub nullifier_tree: NullifierTree<LargeSmt<TreeStorage>>,

    /// Shared database for persisting blocks, accounts, notes, and nullifiers.
    pub db: Arc<Db>,
    /// Shared block store for persisting raw block data.
    pub block_store: Arc<BlockStore>,
    /// Shared in-memory state. The writer publishes new snapshots via `ArcSwap::store()`.
    pub in_memory: Arc<ArcSwap<InMemoryState>>,
}

// WRITE REQUEST
// ================================================================================================

/// A request to apply a new block, sent through the writer channel.
pub struct WriteRequest {
    pub signed_block: SignedBlock,
    pub proving_inputs: Option<BlockProofRequest>,
    pub result_tx: oneshot::Sender<Result<(), ApplyBlockError>>,
}

// PREPARED BLOCK
// ================================================================================================

/// Holds a validated block with its mutations pre-computed, read to be committed.
///
/// Produced by [`BlockWriter::prepare_block_committal`] after all checks pass but before any
/// in-memory tree mutations occur. Consumed by [`BlockWriter::commit_block`].
struct BlockCommittal {
    signed_block: SignedBlock,
    proving_inputs: Option<BlockProofRequest>,
    nullifier_tree_update: NullifierMutationSet,
    account_tree_update: AccountMutationSet,
    notes: Vec<(NoteRecord, Option<miden_protocol::note::Nullifier>)>,
    account_deltas: Vec<AccountDelta>,
    block_num: BlockNumber,
    block_commitment: Word,
}

impl BlockWriter {
    /// Runs the single writer loop. Receives blocks through the channel and applies them
    /// sequentially.
    ///
    /// Signals process termination on fatal errors. Fatal errors leave the writer's in-memory trees
    /// in an inconsistent state that cannot be recovered without a restart.
    pub(crate) async fn run(mut self, termination_ask: mpsc::Sender<String>) {
        while let Some(req) = self.rx.recv().await {
            // Validate the block. No mutations occur here, so any error is safe — the
            // trees remain consistent and the writer can continue.
            let committal =
                match self.prepare_block_committal(req.signed_block, req.proving_inputs).await {
                    Ok(prepared) => prepared,
                    Err(err) => {
                        let _ = req.result_tx.send(Err(err));
                        continue;
                    },
                };

            // Commit the block. In-memory trees are mutated here, so any error is always fatal —
            // the trees are now ahead of persistent storage and the state cannot be reconciled
            // without a restart.
            let result = Box::pin(self.commit_block(committal)).await;
            let fatal_report = result.as_ref().err().map(ErrorReport::as_report);
            // Send the result back to the caller (gRPC service).
            let _ = req.result_tx.send(result);
            // Send the fatal report to the termination ask channel and end the writer loop.
            if let Some(report) = fatal_report {
                let _ = termination_ask.send(report).await;
                break;
            }
        }
    }

    /// Validates the block and computes all required mutations without applying them.
    ///
    /// Performs header validation, loads the current in-memory snapshot, computes tree mutation
    /// sets, validates note records, and collects account deltas. No in-memory state is modified.
    ///
    /// Returns a [`BlockCommittal`] ready to be passed to [`Self::commit_block`].
    #[instrument(target = COMPONENT, skip_all, err, fields(block.number = signed_block.header().block_num().as_u32()))]
    async fn prepare_block_committal(
        &self,
        signed_block: SignedBlock,
        proving_inputs: Option<BlockProofRequest>,
    ) -> Result<BlockCommittal, ApplyBlockError> {
        let header = signed_block.header();
        let body = signed_block.body();
        let block_num = header.block_num();
        let block_commitment = header.commitment();

        self.validate_block_header(header, body).await?;

        // Tree mutation computation and note record building are CPU-bound. Run them inside
        // block_in_place so tokio can evacuate other tasks from this thread for the duration.
        let (nullifier_tree_update, account_tree_update, notes, account_deltas) =
            tokio::task::block_in_place(|| -> Result<_, ApplyBlockError> {
                let (nullifier_tree_update, account_tree_update) =
                    self.compute_tree_mutations(header, body)?;

                let notes = build_note_records(header, body)?;

                let account_deltas =
                    Vec::from_iter(body.updated_accounts().iter().filter_map(|update| {
                        match update.details() {
                            AccountUpdateDetails::Delta(delta) => Some(delta.clone()),
                            AccountUpdateDetails::Private => None,
                        }
                    }));

                Ok((nullifier_tree_update, account_tree_update, notes, account_deltas))
            })?;

        Ok(BlockCommittal {
            signed_block,
            proving_inputs,
            nullifier_tree_update,
            account_tree_update,
            notes,
            account_deltas,
            block_num,
            block_commitment,
        })
    }

    /// Applies a validated block to in-memory state and persists it to storage.
    ///
    /// ## Consistency model
    ///
    /// This function is the sole writer to all state. The writer owns the writable trees directly.
    ///
    /// Because SQLite/files are committed **before** the in-memory swap, there is a window where
    /// the DB is ahead of the in-memory state. Reader methods that combine in-memory and SQLite
    /// data must scope their DB queries by the snapshot's `block_num` to maintain consistency
    /// (see the doc comment on [`super::State`] for the full rules).
    ///
    /// Readers never block: they obtain an `Arc` via `ArcSwap::load_full()`, which performs only
    /// an atomic refcount increment with no data cloning. The atomic swap guarantees readers see
    /// either the old or new state, never a partial update. Readers holding an `Arc` to the old
    /// state are completely unaffected by the swap.
    ///
    /// ## Fatal errors
    ///
    /// Any error returned by this function is fatal. The in-memory trees are mutated before
    /// storage is updated, so a failure leaves the writer in an inconsistent state that cannot
    /// be recovered without a process restart.
    #[instrument(target = COMPONENT, skip_all, err, fields(block.number = prepared.block_num.as_u32()))]
    async fn commit_block(&mut self, prepared: BlockCommittal) -> Result<(), ApplyBlockError> {
        let BlockCommittal {
            signed_block,
            proving_inputs,
            nullifier_tree_update,
            account_tree_update,
            notes,
            account_deltas,
            block_num,
            block_commitment,
        } = prepared;

        // Apply tree mutations and build snapshot-backed read-only copies for InMemoryState.
        // RocksDB writes are synchronous and CPU-bound; run inside block_in_place.
        let (snapshot_nullifier_tree, snapshot_account_tree) = tokio::task::block_in_place(|| {
            self.nullifier_tree
                .apply_mutations(nullifier_tree_update)
                .expect("Unreachable: mutations were computed from the current tree state");

            self.account_tree
                .apply_mutations(account_tree_update)
                .expect("Unreachable: mutations were computed from the current tree state");

            (self.build_snapshot_nullifier_tree(), self.build_snapshot_account_tree())
        });

        let snapshot = self.in_memory.load_full();
        let mut new_blockchain = snapshot.blockchain.clone();
        new_blockchain.push(block_commitment);

        let mut new_forest = snapshot.forest.clone();
        new_forest.apply_block_updates(block_num, account_deltas)?;

        let new_state = InMemoryState {
            block_num,
            nullifier_tree: snapshot_nullifier_tree,
            account_tree: snapshot_account_tree,
            blockchain: new_blockchain,
            forest: new_forest,
        };

        // Save the block to the block store.
        let signed_block_bytes = signed_block.to_bytes();
        self.block_store.save_block(block_num, &signed_block_bytes).await?;

        // Commit to DB. Readers continue to see the old in-memory state (via their Arc) while
        // the DB commits. We ensure consistency by scoping all RPC queries that hit DB data by
        // the block number that is Arc swapped at the end of this function.
        self.db
            .apply_block(signed_block, notes, proving_inputs)
            .await
            .map_err(|err| ApplyBlockError::DbUpdateTaskFailed(err.as_report()))?;

        // Atomically publish the new state. Readers that call snapshot() after this point
        // will see the updated state. Readers holding the old Arc continue unaffected.
        self.in_memory.store(Arc::new(new_state));

        info!(%block_commitment, block_num = block_num.as_u32(), COMPONENT, "apply_block successful");

        Ok(())
    }

    /// Validates that the block header is consistent with the body and follows the previous block.
    async fn validate_block_header(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<(), ApplyBlockError> {
        let tx_commitment = body.transactions().commitment();
        if header.tx_commitment() != tx_commitment {
            return Err(InvalidBlockError::InvalidBlockTxCommitment {
                expected: tx_commitment,
                actual: header.tx_commitment(),
            }
            .into());
        }

        let block_num = header.block_num();
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

        // New block chain root must be equal to the chain MMR root prior to the update.
        let snapshot = self.in_memory.load_full();
        if snapshot.blockchain.peaks().hash_peaks() != header.chain_commitment() {
            return Err(InvalidBlockError::NewBlockInvalidChainCommitment.into());
        }

        Ok(())
    }

    /// Compute mutations for the nullifier tree and account tree.
    fn compute_tree_mutations(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<(NullifierMutationSet, AccountMutationSet), ApplyBlockError> {
        // Nullifiers can be produced only once.
        let duplicate_nullifiers: Vec<_> = body
            .created_nullifiers()
            .iter()
            .filter(|&nullifier| self.nullifier_tree.get_block_num(nullifier).is_some())
            .copied()
            .collect();
        if !duplicate_nullifiers.is_empty() {
            return Err(InvalidBlockError::DuplicatedNullifiers(duplicate_nullifiers).into());
        }

        // Compute update for nullifier tree.
        let nullifier_tree_update = self
            .nullifier_tree
            .compute_mutations(
                body.created_nullifiers()
                    .iter()
                    .map(|nullifier| (*nullifier, header.block_num())),
            )
            .map_err(InvalidBlockError::NewBlockNullifierAlreadySpent)?;

        if nullifier_tree_update.as_mutation_set().root() != header.nullifier_root() {
            return Err(InvalidBlockError::NewBlockInvalidNullifierRoot.into());
        }

        // Compute update for account tree from the writable tree (always in sync with DB).
        let account_tree_update = self
            .account_tree
            .compute_mutations(
                body.updated_accounts()
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
            return Err(InvalidBlockError::NewBlockInvalidAccountRoot.into());
        }

        Ok((nullifier_tree_update, account_tree_update))
    }

    /// Builds a snapshot-backed nullifier tree for the new in-memory state.
    fn build_snapshot_nullifier_tree(&self) -> NullifierTree<LargeSmt<SnapshotTreeStorage>> {
        #[cfg(feature = "rocksdb")]
        {
            self.nullifier_tree.reader()
        }
        #[cfg(not(feature = "rocksdb"))]
        {
            self.nullifier_tree.clone()
        }
    }

    /// Builds a snapshot-backed account tree for the new in-memory state.
    fn build_snapshot_account_tree(&self) -> AccountTreeWithHistory<SnapshotTreeStorage> {
        #[cfg(feature = "rocksdb")]
        {
            self.account_tree.reader()
        }
        #[cfg(not(feature = "rocksdb"))]
        {
            self.account_tree.clone()
        }
    }
}

/// Builds the note tree, validates its root against the header, and collects note records.
fn build_note_records(
    header: &BlockHeader,
    body: &BlockBody,
) -> Result<Vec<(NoteRecord, Option<miden_protocol::note::Nullifier>)>, ApplyBlockError> {
    let block_num = header.block_num();

    let note_tree = body.compute_block_note_tree();
    if note_tree.root() != header.note_root() {
        return Err(InvalidBlockError::NewBlockInvalidNoteRoot.into());
    }

    body.output_notes()
        .map(|(note_index, note)| {
            let (details, nullifier) = match note {
                OutputNote::Public(note) => {
                    (Some(NoteDetails::from(note.as_note())), Some(note.as_note().nullifier()))
                },
                OutputNote::Private(_) => (None, None),
            };

            let inclusion_path = note_tree.open(note_index);

            let note_record = NoteRecord {
                block_num,
                note_index,
                note_id: note.id().as_word(),
                note_commitment: note.to_commitment(),
                metadata: note.metadata().clone(),
                details,
                inclusion_path,
            };

            Ok((note_record, nullifier))
        })
        .collect::<Result<Vec<_>, InvalidBlockError>>()
        .map_err(Into::into)
}
