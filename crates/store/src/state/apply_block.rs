use std::sync::Arc;

use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::account_tree::AccountMutationSet;
use miden_protocol::block::nullifier_tree::NullifierMutationSet;
use miden_protocol::block::{BlockBody, BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::note::{NoteAttachments, NoteDetails, Nullifier};
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use tokio::sync::oneshot;
use tracing::{Instrument, info, info_span, instrument};

use crate::db::NoteRecord;
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::{BlockNotification, State};
use crate::{COMPONENT, HistoricalError};

impl State {
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
    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn apply_block(&self, signed_block: SignedBlock) -> Result<(), ApplyBlockError> {
        let _lock = self.writer.try_lock().map_err(|_| ApplyBlockError::ConcurrentWrite)?;

        let header = signed_block.header();
        let body = signed_block.body();

        let block_num = header.block_num();
        let block_commitment = header.commitment();

        self.validate_block_header(header, body).await?;

        // Save the block to the block store. In a case of a rolled-back DB transaction, the
        // in-memory state will be unchanged, but the file might still be written. Such blocks
        // should be considered candidates, not finalized blocks.
        let signed_block_bytes = signed_block.to_bytes();
        // Clone before moving into the block-save task so we can cache for replicas at commit.
        let cache_bytes = signed_block_bytes.clone();
        let store = Arc::clone(&self.block_store);
        let block_save_task = tokio::spawn(
            async move { store.save_block(block_num, &signed_block_bytes).await }.in_current_span(),
        );

        let (
            nullifier_tree_old_root,
            nullifier_tree_update,
            account_tree_old_root,
            account_tree_update,
        ) = self.compute_tree_mutations(header, body).await?;

        let notes = Self::build_note_records(header, body)?;

        // Signals the transaction is ready to be committed, and the write lock can be acquired.
        let (allow_acquire, acquired_allowed) = oneshot::channel::<()>();
        // Signals the write lock has been acquired, and the transaction can be committed.
        let (inform_acquire_done, acquire_done) = oneshot::channel::<()>();

        // Extract public account updates with deltas before block is moved into async task. Private
        // accounts are filtered out since they don't expose their state changes.
        let account_deltas =
            Vec::from_iter(body.updated_accounts().iter().filter_map(
                |update| match update.details() {
                    AccountUpdateDetails::Delta(delta) => Some(delta.clone()),
                    AccountUpdateDetails::Private => None,
                },
            ));

        // The DB and in-memory state updates need to be synchronized and are partially overlapping.
        // Namely, the DB transaction only proceeds after this task acquires the in-memory write
        // lock. This requires the DB update to run concurrently, so a new task is spawned.
        let db = Arc::clone(&self.db);
        let db_update_task = tokio::spawn(
            async move { db.apply_block(allow_acquire, acquire_done, signed_block, notes).await }
                .in_current_span(),
        );

        // Wait for the message from the DB update task, that we ready to commit the DB transaction.
        acquired_allowed
            .instrument(info_span!(target: COMPONENT, "await_db_readiness"))
            .await
            .map_err(ApplyBlockError::ClosedChannel)?;

        // Awaiting the block saving task to complete without errors.
        block_save_task.await??;

        self.with_inner_write_blocking(|inner| {
            // We need to check that neither the nullifier tree nor the account tree have changed
            // while we were waiting for the DB preparation task to complete. If either of them did
            // change, we do not proceed with in-memory and database updates, since it may lead to
            // an inconsistent state.
            if inner.nullifier_tree.root() != nullifier_tree_old_root
                || inner.account_tree.root_latest() != account_tree_old_root
            {
                return Err(ApplyBlockError::ConcurrentWrite);
            }

            // Notify the DB update task that the write lock has been acquired, so it can commit the
            // DB transaction.
            inform_acquire_done
                .send(())
                .map_err(|_| ApplyBlockError::DbUpdateTaskFailed("Receiver was dropped".into()))?;

            // TODO: shutdown #91 Await for successful commit of the DB transaction. If the commit
            // fails, we mustn't change in-memory state, so we return a block applying error and
            // don't proceed with in-memory updates.
            tokio::runtime::Handle::current()
                .block_on(db_update_task)?
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
        })?;

        self.with_forest_write_blocking(|forest| {
            forest.apply_block_updates(block_num, account_deltas)
        })?;

        // Push to cache and notify replica subscribers.
        self.block_cache.push(block_num, BlockNotification::new(block_num, cache_bytes));
        let _ = self.committed_tip_tx.send(block_num);

        info!(%block_commitment, block_num = block_num.as_u32(), COMPONENT, "apply_block successful");

        Ok(())
    }

    /// Saves the proving inputs for the given block to the block store.
    pub async fn save_proving_inputs(
        &self,
        block_num: BlockNumber,
        proving_inputs: &BlockProofRequest,
    ) -> std::io::Result<()> {
        self.block_store
            .save_proving_inputs(block_num, &proving_inputs.to_bytes())
            .await
    }

    /// Validates that the block header is consistent with the block body and the current state.
    #[instrument(target = COMPONENT, skip_all, err)]
    async fn validate_block_header(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<(), ApplyBlockError> {
        // Validate that header and body match.
        let tx_commitment = body.transactions().commitment();
        if header.tx_commitment() != tx_commitment {
            return Err(InvalidBlockError::InvalidBlockTxCommitment {
                expected: tx_commitment,
                actual: header.tx_commitment(),
            }
            .into());
        }

        let block_num = header.block_num();

        // Validate that the applied block is the next block in sequence.
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

    /// Computes nullifier and account tree mutations, validating roots against the block header.
    #[instrument(target = COMPONENT, skip_all, err)]
    async fn compute_tree_mutations(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<(Word, NullifierMutationSet, Word, AccountMutationSet), ApplyBlockError> {
        self.with_inner_read_blocking(|inner| {
            let block_num = header.block_num();

            // nullifiers can be produced only once
            let duplicate_nullifiers: Vec<_> = body
                .created_nullifiers()
                .iter()
                .filter(|&nullifier| inner.nullifier_tree.get_block_num(nullifier).is_some())
                .copied()
                .collect();
            if !duplicate_nullifiers.is_empty() {
                return Err(InvalidBlockError::DuplicatedNullifiers(duplicate_nullifiers).into());
            }

            // new_block.chain_root must be equal to the chain MMR root prior to the update
            let peaks = inner.blockchain.peaks();
            if peaks.hash_peaks() != header.chain_commitment() {
                return Err(InvalidBlockError::NewBlockInvalidChainCommitment.into());
            }

            // compute update for nullifier tree
            let nullifier_tree_update = inner
                .nullifier_tree
                .compute_mutations(
                    body.created_nullifiers().iter().map(|nullifier| (*nullifier, block_num)),
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

            Ok((
                inner.nullifier_tree.root(),
                nullifier_tree_update,
                inner.account_tree.root_latest(),
                account_tree_update,
            ))
        })
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
