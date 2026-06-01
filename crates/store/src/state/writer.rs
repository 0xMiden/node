//! Serialised block-write path for the store state.
//!
//! A single [`BlockWriter`] task owns the mutable trees and processes incoming [`WriteRequest`]s
//! one at a time via an mpsc channel. After each successful commit it publishes a new
//! [`InMemoryState`] snapshot via an [`ArcSwap`], making the updated trees immediately visible to
//! wait-free readers.

use std::sync::Arc;

use arc_swap::ArcSwap;
use miden_node_utils::ErrorReport;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::account_tree::AccountMutationSet;
use miden_protocol::block::nullifier_tree::{NullifierMutationSet, NullifierTree};
use miden_protocol::block::{BlockBody, BlockHeader, BlockNumber, Blockchain, SignedBlock};
use miden_protocol::crypto::merkle::smt::LargeSmt;
use miden_protocol::note::{NoteAttachments, NoteDetails, Nullifier};
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tracing::{Instrument, info, info_span, instrument};

use crate::account_state_forest::{AccountStateForest, AccountStateForestBackend};
use crate::accounts::AccountTreeWithHistory;
use crate::blocks::BlockStore;
use crate::db::{Db, NoteRecord};
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::loader::TreeStorage;
use crate::state::{BlockCache, BlockNotification, InMemoryState};
use crate::{COMPONENT, HistoricalError};

// WRITE REQUEST
// ================================================================================================

/// A request to apply a block, paired with a one-shot channel for the result.
pub struct WriteRequest {
    pub signed_block: SignedBlock,
    pub result_tx: oneshot::Sender<Result<(), ApplyBlockError>>,
}

// WRITE HANDLE
// ================================================================================================

/// Cloneable handle for sending block-write requests to the [`BlockWriter`] task.
#[derive(Clone)]
pub struct WriteHandle {
    tx: mpsc::Sender<WriteRequest>,
}

impl WriteHandle {
    pub(super) fn new(tx: mpsc::Sender<WriteRequest>) -> Self {
        Self { tx }
    }

    /// Sends a block to the writer task and awaits its result.
    pub async fn apply_block(&self, signed_block: SignedBlock) -> Result<(), ApplyBlockError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.tx
            .send(WriteRequest { signed_block, result_tx })
            .await
            .map_err(|e| ApplyBlockError::WriterTaskSendFailed(e.to_string()))?;
        result_rx.await.map_err(ApplyBlockError::WriterTaskRecvFailed)?
    }
}

// BLOCK WRITER
// ================================================================================================

/// Single-task owner of the mutable trees. Processes [`WriteRequest`]s serially.
pub(super) struct BlockWriter {
    pub db: Arc<Db>,
    pub block_store: Arc<BlockStore>,
    pub in_memory: Arc<ArcSwap<InMemoryState>>,
    pub forest: Arc<RwLock<AccountStateForest<AccountStateForestBackend>>>,
    pub committed_tip_tx: Arc<watch::Sender<BlockNumber>>,
    pub block_cache: BlockCache,
    pub termination_ask: tokio::sync::mpsc::Sender<ApplyBlockError>,
    pub rx: mpsc::Receiver<WriteRequest>,
    /// The mutable nullifier tree owned by this writer.
    pub nullifier_tree: NullifierTree<LargeSmt<TreeStorage>>,
    /// The mutable account tree owned by this writer.
    pub account_tree: AccountTreeWithHistory<TreeStorage>,
    /// The blockchain MMR owned by this writer.
    pub blockchain: Blockchain,
}

impl BlockWriter {
    /// Runs the writer loop, processing requests until the channel closes.
    pub async fn run(mut self) {
        while let Some(req) = self.rx.recv().await {
            let result = self.process_request(req.signed_block).await;
            let _ = req.result_tx.send(result);
        }
    }

    #[instrument(target = COMPONENT, skip_all, err)]
    async fn process_request(&mut self, signed_block: SignedBlock) -> Result<(), ApplyBlockError> {
        let header = signed_block.header();
        let body = signed_block.body();

        let block_num = header.block_num();
        let block_commitment = header.commitment();

        self.validate_block_header(header, body).await?;

        // Save the block to the block store concurrently with computing mutations.
        let signed_block_bytes = signed_block.to_bytes();
        let cache_bytes = signed_block_bytes.clone();
        let store = Arc::clone(&self.block_store);
        let block_save_task = tokio::spawn(
            async move { store.save_block(block_num, &signed_block_bytes).await }.in_current_span(),
        );

        let (nullifier_tree_update, account_tree_update) =
            self.compute_tree_mutations(header, body)?;

        let notes = Self::build_note_records(header, body)?;

        // Extract public account deltas before `signed_block` is moved.
        let account_deltas =
            Vec::from_iter(body.updated_accounts().iter().filter_map(
                |update| match update.details() {
                    AccountUpdateDetails::Delta(delta) => Some(delta.clone()),
                    AccountUpdateDetails::Private => None,
                },
            ));

        // Commit to the database.
        let db = Arc::clone(&self.db);
        db.apply_block(signed_block, notes)
            .instrument(info_span!(target: COMPONENT, "db_apply_block"))
            .await
            .map_err(|err| ApplyBlockError::DbUpdateTaskFailed(err.as_report()))?;

        // Wait for the block store save to complete.
        block_save_task.await??;

        // Apply mutations to the owned mutable trees.
        tokio::task::block_in_place(|| {
            self.nullifier_tree
                .apply_mutations(nullifier_tree_update)
                .expect("nullifier tree mutation should succeed after validation");

            self.account_tree
                .apply_mutations(account_tree_update)
                .expect("account tree mutation should succeed after validation");

            self.blockchain.push(block_commitment);

            // Publish a new snapshot via ArcSwap.
            let snapshot = Arc::new(InMemoryState {
                block_num,
                nullifier_tree: self
                    .nullifier_tree
                    .reader()
                    .expect("nullifier tree snapshot creation should not fail"),
                account_tree: self.account_tree.reader(),
                blockchain: self.blockchain.clone(),
            });
            self.in_memory.store(snapshot);

            Ok::<(), ApplyBlockError>(())
        })?;

        // Update the forest.
        tokio::task::block_in_place(|| {
            let mut forest = self.forest.blocking_write();
            forest.apply_block_updates(block_num, account_deltas)
        })?;

        // Notify replica subscribers.
        self.block_cache.push(block_num, BlockNotification::new(block_num, cache_bytes));
        let _ = self.committed_tip_tx.send(block_num);

        info!(%block_commitment, block_num = block_num.as_u32(), COMPONENT, "apply_block successful");

        Ok(())
    }

    /// Validates that the block header is consistent with the block body and the current state.
    #[instrument(target = COMPONENT, skip_all, err)]
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

        Ok(())
    }

    /// Computes nullifier and account tree mutations from the owned mutable trees.
    #[instrument(target = COMPONENT, skip_all, err)]
    fn compute_tree_mutations(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<(NullifierMutationSet, AccountMutationSet), ApplyBlockError> {
        let block_num = header.block_num();

        let duplicate_nullifiers: Vec<_> = body
            .created_nullifiers()
            .iter()
            .filter(|&nullifier| self.nullifier_tree.get_block_num(nullifier).is_some())
            .copied()
            .collect();
        if !duplicate_nullifiers.is_empty() {
            return Err(InvalidBlockError::DuplicatedNullifiers(duplicate_nullifiers).into());
        }

        let peaks = self.blockchain.peaks();
        if peaks.hash_peaks() != header.chain_commitment() {
            return Err(InvalidBlockError::NewBlockInvalidChainCommitment.into());
        }

        let nullifier_tree_update = self
            .nullifier_tree
            .compute_mutations(
                body.created_nullifiers().iter().map(|nullifier| (*nullifier, block_num)),
            )
            .map_err(InvalidBlockError::NewBlockNullifierAlreadySpent)?;

        if nullifier_tree_update.as_mutation_set().root() != header.nullifier_root() {
            let _ = self.termination_ask.try_send(ApplyBlockError::InvalidBlockError(
                InvalidBlockError::NewBlockInvalidNullifierRoot,
            ));
            return Err(InvalidBlockError::NewBlockInvalidNullifierRoot.into());
        }

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
            let _ = self.termination_ask.try_send(ApplyBlockError::InvalidBlockError(
                InvalidBlockError::NewBlockInvalidAccountRoot,
            ));
            return Err(InvalidBlockError::NewBlockInvalidAccountRoot.into());
        }

        Ok((nullifier_tree_update, account_tree_update))
    }

    /// Builds note records with inclusion proofs from the block body.
    #[instrument(target = COMPONENT, skip_all, err)]
    fn build_note_records(
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<Vec<(NoteRecord, Option<Nullifier>)>, ApplyBlockError> {
        let block_num = header.block_num();

        let note_tree = body.compute_block_note_tree();
        if note_tree.root() != header.note_root() {
            return Err(InvalidBlockError::NewBlockInvalidNoteRoot.into());
        }

        let notes = body
            .output_notes()
            .map(|(note_index, note)| {
                let (details, attachments, nullifier) = match note {
                    OutputNote::Public(public) => (
                        Some(NoteDetails::from(public.as_note())),
                        public.as_note().attachments().clone(),
                        Some(public.as_note().nullifier()),
                    ),
                    OutputNote::Private(_) => (None, NoteAttachments::empty(), None),
                };

                let inclusion_path = note_tree.open(note_index);

                let note_record = NoteRecord {
                    block_num,
                    note_index,
                    note_id: note.id().as_word(),
                    metadata: *note.metadata(),
                    details,
                    attachments,
                    inclusion_path,
                };

                Ok((note_record, nullifier))
            })
            .collect::<Result<Vec<_>, InvalidBlockError>>()?;

        Ok(notes)
    }
}
