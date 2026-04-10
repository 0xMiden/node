use std::sync::Arc;

use miden_node_proto::BlockProofRequest;
use miden_node_utils::ErrorReport;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::SignedBlock;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::crypto::merkle::smt::LargeSmt;
use miden_protocol::note::NoteDetails;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use tokio::sync::{mpsc, oneshot};
use tracing::{Instrument, info, info_span, instrument};

use crate::accounts::AccountTreeWithHistory;
use crate::db::NoteRecord;
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::loader::TreeStorage;
use crate::state::{InMemoryState, State};
use crate::{COMPONENT, HistoricalError};

/// A request to apply a new block, sent through the writer channel.
pub struct WriteRequest {
    pub signed_block: SignedBlock,
    pub proving_inputs: Option<BlockProofRequest>,
    pub result_tx: oneshot::Sender<Result<(), ApplyBlockError>>,
}

/// Runs the single writer loop. Receives blocks through the channel and applies them
/// sequentially. The writer owns the writable trees — no locks or interior mutability needed.
pub(crate) async fn writer_loop(
    mut rx: mpsc::Receiver<WriteRequest>,
    state: Arc<State>,
    mut nullifier_tree: NullifierTree<LargeSmt<TreeStorage>>,
    mut account_tree: AccountTreeWithHistory<TreeStorage>,
) {
    while let Some(req) = rx.recv().await {
        let result = Box::pin(apply_block_inner(
            &state,
            &mut nullifier_tree,
            &mut account_tree,
            req.signed_block,
            req.proving_inputs,
        ))
        .await;
        let _ = req.result_tx.send(result);
    }
}

/// Apply changes of a new block to the DB and in-memory data structures.
///
/// ## Consistency model
///
/// This function is the sole writer to all state. The writer owns the writable trees directly
/// (no locks or interior mutability). It applies mutations, then creates a new `InMemoryState`
/// with snapshot-backed read-only copies and atomically swaps the pointer.
///
/// Readers never block: they obtain an `Arc` via `ArcSwap::load_full()`, which performs only an
/// atomic refcount increment with no data cloning. The atomic swap guarantees readers see either
/// the old or new state, never a partial update. Readers holding an `Arc` to the old state are
/// completely unaffected by the swap.
///
/// ## Performance
///
/// No deep clone of tree data occurs in `RocksDB` mode. The snapshot-backed trees read directly
/// from `RocksDB` snapshots. Readers pay only an atomic refcount bump per `snapshot()` call.
#[expect(clippy::too_many_lines)]
#[instrument(target = COMPONENT, skip_all, err, fields(block.number = signed_block.header().block_num().as_u32()))]
async fn apply_block_inner(
    state: &State,
    nullifier_tree: &mut NullifierTree<LargeSmt<TreeStorage>>,
    account_tree: &mut AccountTreeWithHistory<TreeStorage>,
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

    // Load the current in-memory state snapshot for validation (wait-free).
    let snapshot = state.in_memory.load_full();

    // Compute mutations required for updating account and nullifier trees.
    let (nullifier_tree_update, account_tree_update) = {
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
        let peaks = snapshot.blockchain.peaks();
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

        // Compute update for account tree from the writable tree (always in sync with DB).
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

    // Commit to DB. Readers continue to see the old in-memory state (via their Arc) while
    // the DB commits.
    state
        .db
        .apply_block(signed_block, notes, proving_inputs)
        .await
        .map_err(|err| ApplyBlockError::DbUpdateTaskFailed(err.as_report()))?;

    // Await the block store save task.
    block_save_task.await??;

    // Apply mutations to the writable trees (writes to RocksDB).
    nullifier_tree
        .apply_mutations(nullifier_tree_update)
        .expect("Unreachable: mutations were computed from the current tree state");

    account_tree
        .apply_mutations(account_tree_update)
        .expect("Unreachable: mutations were computed from the current tree state");

    // Build a new read-only InMemoryState with snapshot-backed trees.
    // The snapshots capture the RocksDB state after mutations have been applied.
    let snapshot_nullifier_tree = {
        #[cfg(feature = "rocksdb")]
        {
            use miden_protocol::block::nullifier_tree::NullifierTree;

            use crate::state::loader;

            let snapshot_storage = miden_large_smt_backend_rocksdb::RocksDbSnapshotStorage::new(
                std::sync::Arc::clone(&state.nullifier_db),
            );
            let snapshot_smt = loader::load_smt(snapshot_storage)
                .expect("Unreachable: snapshot reads from data just written by apply_mutations");
            NullifierTree::new_unchecked(snapshot_smt)
        }
        #[cfg(not(feature = "rocksdb"))]
        {
            nullifier_tree.clone()
        }
    };

    let snapshot_account_tree = {
        #[cfg(feature = "rocksdb")]
        {
            use crate::accounts::AccountTreeWithHistory;
            use crate::state::loader;

            let snapshot_storage = miden_large_smt_backend_rocksdb::RocksDbSnapshotStorage::new(
                std::sync::Arc::clone(&state.account_db),
            );
            let snapshot_smt = loader::load_smt(snapshot_storage)
                .expect("Unreachable: snapshot reads from data just written by apply_mutations");
            let snapshot_tree =
                miden_protocol::block::account_tree::AccountTree::new_unchecked(snapshot_smt);

            AccountTreeWithHistory::from_parts(
                snapshot_tree,
                account_tree.block_number_latest(),
                account_tree.overlays().clone(),
            )
        }
        #[cfg(not(feature = "rocksdb"))]
        {
            account_tree.clone()
        }
    };

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

    // Atomically publish the new state. Readers that call snapshot() after this point
    // will see the updated state. Readers holding the old Arc continue unaffected.
    state.in_memory.store(Arc::new(new_state));

    info!(%block_commitment, block_num = block_num.as_u32(), COMPONENT, "apply_block successful");

    Ok(())
}
