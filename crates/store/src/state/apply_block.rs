use std::sync::Arc;

use miden_node_utils::ErrorReport;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::SignedBlock;
use miden_protocol::note::NoteDetails;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::Serializable;
use tokio::sync::oneshot;
use tracing::{Instrument, info, info_span, instrument};

use crate::db::NoteRecord;
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::State;
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
    #[allow(clippy::too_many_lines)]
    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn apply_block(&self, signed_block: SignedBlock) -> Result<(), ApplyBlockError> {
        let _lock = self.writer.try_lock().map_err(|_| ApplyBlockError::ConcurrentWrite)?;

        let header = signed_block.header();
        let body = signed_block.body();

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
        let block_commitment = header.commitment();

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

        // Save the block to the block store. In a case of a rolled-back DB transaction, the
        // in-memory state will be unchanged, but the block might still be written into the
        // block store. Thus, such block should be considered as block candidates, but not
        // finalized blocks. So we should check for the latest block when getting block from
        // the store.
        let signed_block_bytes = signed_block.to_bytes();
        let store = Arc::clone(&self.block_store);
        let block_save_task = tokio::spawn(
            async move { store.save_block(block_num, &signed_block_bytes).await }.in_current_span(),
        );

        // Scope to read in-memory data, compute mutations required for updating account
        // and nullifier trees, and validate the request.
        let (
            nullifier_tree_old_root,
            nullifier_tree_update,
            account_tree_old_root,
            account_tree_update,
        ) = {
            let inner = self.inner.read().await;

            let _span = info_span!(target: COMPONENT, "update_in_memory_structs").entered();

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

            (
                inner.nullifier_tree.root(),
                nullifier_tree_update,
                inner.account_tree.root_latest(),
                account_tree_update,
            )
        };

        // Build note tree.
        let note_tree = body.compute_block_note_tree();
        if note_tree.root() != header.note_root() {
            return Err(InvalidBlockError::NewBlockInvalidNoteRoot.into());
        }

        let notes = body
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

        // Signals the transaction is ready to be committed, and the write lock can be acquired.
        let (allow_acquire, acquired_allowed) = oneshot::channel::<()>();
        // Signals the write lock has been acquired, and the transaction can be committed.
        let (inform_acquire_done, acquire_done) = oneshot::channel::<()>();

        // Extract public account updates with deltas before block is moved into async task.
        // Private accounts are filtered out since they don't expose their state changes.
        let account_deltas =
            Vec::from_iter(body.updated_accounts().iter().filter_map(
                |update| match update.details() {
                    AccountUpdateDetails::Delta(delta) => Some(delta.clone()),
                    AccountUpdateDetails::Private => None,
                },
            ));

        // The DB and in-memory state updates need to be synchronized and are partially
        // overlapping. Namely, the DB transaction only proceeds after this task acquires the
        // in-memory write lock. This requires the DB update to run concurrently, so a new task is
        // spawned.
        let db = Arc::clone(&self.db);
        let db_update_task = tokio::spawn(
            async move { db.apply_block(allow_acquire, acquire_done, signed_block, notes).await }
                .in_current_span(),
        );

        // Wait for the message from the DB update task, that we ready to commit the DB transaction.
        acquired_allowed.await.map_err(ApplyBlockError::ClosedChannel)?;

        // Awaiting the block saving task to complete without errors.
        block_save_task.await??;

        // Scope to update the in-memory data.
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
            // the DB transaction.
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
}
