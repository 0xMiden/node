use std::sync::Arc;
use std::sync::atomic::Ordering;

use miden_node_proto::BlockProofRequest;
use miden_node_utils::ErrorReport;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::SignedBlock;
use miden_protocol::note::NoteDetails;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use tokio::sync::{mpsc, oneshot};
use tracing::{Instrument, info, info_span, instrument};

use crate::db::NoteRecord;
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::State;
use crate::{COMPONENT, HistoricalError};

/// A request to apply a new block, sent through the writer channel.
pub struct WriteRequest {
    pub signed_block: SignedBlock,
    pub proving_inputs: Option<BlockProofRequest>,
    pub result_tx: oneshot::Sender<Result<(), ApplyBlockError>>,
}

/// Runs the single writer loop. Receives blocks through the channel and applies them
/// sequentially. Channel serialization guarantees no concurrent writers — no mutex needed.
pub(crate) async fn writer_loop(mut rx: mpsc::Receiver<WriteRequest>, state: Arc<State>) {
    while let Some(req) = rx.recv().await {
        let result =
            Box::pin(apply_block_inner(&state, req.signed_block, req.proving_inputs)).await;
        let _ = req.result_tx.send(result);
    }
}

/// Apply changes of a new block to the DB and in-memory data structures.
///
/// ## Consistency model
///
/// This function is the sole writer to all in-memory state. The nullifier tree (backed by
/// `RocksDB` with MVCC) is accessed lock-free via [`WriterGuard`]. The in-memory structures
/// (`account_tree`, `blockchain`, `forest`) are protected by [`RwLock`]: the writer acquires
/// read locks during validation and write locks during the brief mutation phase.
///
/// The DB transaction is committed independently. Readers gate visibility through the atomic
/// block counter, so the brief window where the DB has block N+1 but the counter still says N
/// is invisible to readers.
#[expect(clippy::too_many_lines)]
#[instrument(target = COMPONENT, skip_all, err, fields(block.number = signed_block.header().block_num().as_u32()))]
async fn apply_block_inner(
    state: &State,
    signed_block: SignedBlock,
    proving_inputs: Option<BlockProofRequest>,
) -> Result<(), ApplyBlockError> {
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
    let prev_block = state
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

    // Save the block to the block store concurrently.
    // In a case of a rolled-back DB transaction, the in-memory state will be unchanged, but
    // the block might still be written into the block store. Such blocks should be considered
    // as candidates, not finalized blocks.
    let signed_block_bytes = signed_block.to_bytes();
    let store = Arc::clone(&state.block_store);
    let block_save_task = tokio::spawn(
        async move { store.save_block(block_num, &signed_block_bytes).await }.in_current_span(),
    );

    // Compute mutations required for updating account and nullifier trees.
    // The nullifier tree uses WriterGuard (RocksDB MVCC — safe for concurrent access).
    // The account tree and blockchain use RwLock (in-memory — need read lock for validation).
    let (nullifier_tree_update, account_tree_update) = {
        let nullifier_tree = unsafe { state.nullifier_tree.as_mut() };
        let account_tree = state.account_tree.read().await;
        let blockchain = state.blockchain.read().await;

        let _span = info_span!(target: COMPONENT, "compute_tree_mutations").entered();

        // Nullifiers can be produced only once.
        let duplicate_nullifiers: Vec<_> = body
            .created_nullifiers()
            .iter()
            .filter(|&nullifier| nullifier_tree.get_block_num(nullifier).is_some())
            .copied()
            .collect();
        if !duplicate_nullifiers.is_empty() {
            return Err(InvalidBlockError::DuplicatedNullifiers(duplicate_nullifiers).into());
        }

        // new_block.chain_root must be equal to the chain MMR root prior to the update.
        let peaks = blockchain.peaks();
        if peaks.hash_peaks() != header.chain_commitment() {
            return Err(InvalidBlockError::NewBlockInvalidChainCommitment.into());
        }

        // Compute update for nullifier tree.
        let nullifier_tree_update = nullifier_tree
            .compute_mutations(
                body.created_nullifiers().iter().map(|nullifier| (*nullifier, block_num)),
            )
            .map_err(InvalidBlockError::NewBlockNullifierAlreadySpent)?;

        if nullifier_tree_update.as_mutation_set().root() != header.nullifier_root() {
            let _ = state.termination_ask.try_send(ApplyBlockError::InvalidBlockError(
                InvalidBlockError::NewBlockInvalidNullifierRoot,
            ));
            return Err(InvalidBlockError::NewBlockInvalidNullifierRoot.into());
        }

        // Compute update for account tree.
        let account_tree_update = account_tree
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
            let _ = state.termination_ask.try_send(ApplyBlockError::InvalidBlockError(
                InvalidBlockError::NewBlockInvalidAccountRoot,
            ));
            return Err(InvalidBlockError::NewBlockInvalidAccountRoot.into());
        }

        (nullifier_tree_update, account_tree_update)
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
        .collect::<Result<Vec<_>, InvalidBlockError>>()?;

    // Extract public account deltas before block is moved into the DB task.
    let account_deltas =
        Vec::from_iter(body.updated_accounts().iter().filter_map(
            |update| match update.details() {
                AccountUpdateDetails::Delta(delta) => Some(delta.clone()),
                AccountUpdateDetails::Private => None,
            },
        ));

    // Commit to DB. No oneshot synchronization dance needed — readers gate visibility
    // through the atomic block counter, not through DB transaction timing.
    state
        .db
        .apply_block(signed_block, notes, proving_inputs)
        .await
        .map_err(|err| ApplyBlockError::DbUpdateTaskFailed(err.as_report()))?;

    // Await the block store save task.
    block_save_task.await??;

    // Apply in-memory mutations.

    // Nullifier tree: lock-free via WriterGuard (RocksDB MVCC).
    // SAFETY: This is the single writer task, serialized by the channel.
    unsafe {
        state
            .nullifier_tree
            .as_mut()
            .apply_mutations(nullifier_tree_update)
            .expect("Unreachable: mutations were computed from the current tree state");
    }

    // In-memory structures: acquire write locks for the brief mutation phase.
    {
        let mut account_tree = state.account_tree.write().await;
        let mut blockchain = state.blockchain.write().await;
        let mut forest = state.forest.write().await;

        account_tree
            .apply_mutations(account_tree_update)
            .expect("Unreachable: mutations were computed from the current tree state");

        blockchain.push(block_commitment);

        forest.apply_block_updates(block_num, account_deltas)?;
    }

    // PUBLISH: Advance the atomic block counter with Release ordering.
    // All mutations above are guaranteed visible to any reader that subsequently loads this
    // counter with Acquire ordering.
    state.committed_block_num.store(block_num.as_u32(), Ordering::Release);

    info!(%block_commitment, block_num = block_num.as_u32(), COMPONENT, "apply_block successful");

    Ok(())
}
