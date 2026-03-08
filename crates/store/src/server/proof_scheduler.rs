//! Background task that drives deferred block proving.
//!
//! The [`proof_scheduler`] is spawned as an internal Store task. It:
//!
//! 1. Tracks `chain_tip` via a [`watch::Receiver<BlockNumber>`] and `latest_proven_block` locally.
//! 2. Maintains up to [`MAX_CONCURRENT_PROOFS`] in-flight proving jobs via a [`JoinSet`].
//! 3. Marks blocks as proven in the database **sequentially** — a block is only marked after all
//!    its ancestors have been marked. Completed proofs that arrive out-of-order are buffered
//!    locally until the sequential gap is filled.
//! 4. On transient errors (DB reads, prover failures, timeouts), the failed block is re-queued for
//!    proving while other in-flight jobs continue uninterrupted.
//! 5. On fatal errors (e.g. deserialization failures, missing proving inputs), the scheduler
//!    returns the error to the caller for node shutdown.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use miden_protocol::block::{BlockNumber, BlockProof};
use miden_protocol::utils::Serializable;
use miden_remote_prover_client::RemoteProverClientError;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, info, instrument};

use crate::COMPONENT;
use crate::blocks::BlockStore;
use crate::db::Db;
use crate::errors::{DatabaseError, ProofSchedulerError};
use crate::server::block_prover_client::{BlockProver, StoreProverError};

// CONSTANTS
// ================================================================================================

/// Overall timeout for proving a single block.
const BLOCK_PROVE_TIMEOUT: Duration = Duration::from_mins(4);

/// Maximum number of blocks being proven concurrently.
const MAX_CONCURRENT_PROOFS: usize = 8;

// PROOF SCHEDULER
// ================================================================================================

/// Spawns the proof scheduler as a background tokio task.
///
/// The scheduler uses `chain_tip_rx` to learn about newly committed blocks and
/// `latest_proven_block` as the starting point for sequential proof tracking.
///
/// Returns a [`JoinHandle`] that resolves when the scheduler encounters a fatal error or
/// completes unexpectedly.
pub fn spawn(
    db: Arc<Db>,
    block_prover: Arc<BlockProver>,
    block_store: Arc<BlockStore>,
    chain_tip_rx: watch::Receiver<BlockNumber>,
    latest_proven_block: BlockNumber,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(run(db, block_prover, block_store, chain_tip_rx, latest_proven_block))
}

/// Main loop of the proof scheduler.
///
/// Maintains a pool of concurrent proving jobs via [`JoinSet`], fills them up to
/// [`MAX_CONCURRENT_PROOFS`], and drains completed results in block-number order.
///
/// Returns `Err` on irrecoverable errors (missing/corrupt proving inputs, DB write failures).
/// Transient errors are retried internally.
async fn run(
    db: Arc<Db>,
    block_prover: Arc<BlockProver>,
    block_store: Arc<BlockStore>,
    mut chain_tip_rx: watch::Receiver<BlockNumber>,
    latest_proven_block: BlockNumber,
) -> anyhow::Result<()> {
    info!(target: COMPONENT, %latest_proven_block, "Proof scheduler started");

    // The latest block that has been sequentially marked as proven in the DB.
    let mut latest_proven = latest_proven_block;
    // The current chain tip as observed from the watch channel.
    let mut chain_tip = *chain_tip_rx.borrow_and_update();
    // Completed proof results waiting for sequential drain.
    let mut results: BTreeSet<BlockNumber> = BTreeSet::new();
    // In-flight proving tasks.
    let mut join_set: JoinSet<anyhow::Result<BlockNumber>> = JoinSet::new();
    // Block numbers currently being proven.
    // Used to avoid double-scheduling a block that failed and needs retry.
    let mut in_flight: BTreeSet<BlockNumber> = BTreeSet::new();
    // Blocks that have been committed and need to be scheduled for proving.
    let mut pending: BTreeSet<BlockNumber> = BTreeSet::new();

    // Seed the pending set with all blocks that need proving.
    for block_num in block_range(latest_proven.child(), chain_tip) {
        pending.insert(block_num);
    }

    loop {
        // Fill the job pool up to capacity from the pending set.
        while in_flight.len() < MAX_CONCURRENT_PROOFS {
            let Some(&block_num) = pending.first() else {
                break;
            };
            pending.remove(&block_num);
            in_flight.insert(block_num);

            let db = Arc::clone(&db);
            let block_prover = Arc::clone(&block_prover);
            let block_store = Arc::clone(&block_store);
            join_set.spawn(async move {
                prove_and_save(&db, &block_prover, &block_store, block_num).await
            });
        }

        // If there's nothing in flight and nothing pending, wait for new blocks.
        if in_flight.is_empty() && pending.is_empty() {
            if chain_tip_rx.changed().await.is_err() {
                info!(target: COMPONENT, "Chain tip channel closed, proof scheduler exiting");
                return Ok(());
            }
            enqueue_new_blocks(&chain_tip_rx, &mut chain_tip, &mut pending);
            continue;
        }

        // Wait for either a job to complete or the chain tip to advance.
        tokio::select! {
            // Proving task completed.
            Some(join_result) = join_set.join_next() => {
                match join_result {
                    Ok(Ok(block_num)) => {
                        info!(target: COMPONENT, %block_num, "Block proof completed");
                        in_flight.remove(&block_num);
                        results.insert(block_num);
                    },
                    Ok(Err(err)) => return Err(err),
                    Err(join_err) => {
                        anyhow::bail!("Proof task panicked: {join_err}")
                    },
                }
            },

            // New chain tip received.
            result = chain_tip_rx.changed() => {
                if result.is_err() {
                    info!(target: COMPONENT, "Chain tip channel closed, proof scheduler exiting");
                    return Ok(());
                }
                enqueue_new_blocks(&chain_tip_rx, &mut chain_tip, &mut pending);
            },
        }

        // Drain completed proofs sequentially.
        drain_sequential_results(&db, &mut results, &mut latest_proven).await?;
    }
}

/// Reads and sets the latest chain tip from the watch channel and adds any new block numbers to the
/// pending set.
fn enqueue_new_blocks(
    chain_tip_rx: &watch::Receiver<BlockNumber>,
    chain_tip: &mut BlockNumber,
    pending: &mut BTreeSet<BlockNumber>,
) {
    let new_chain_tip = *chain_tip_rx.borrow();
    for block_num in block_range(chain_tip.child(), new_chain_tip) {
        pending.insert(block_num);
    }
    *chain_tip = new_chain_tip;
}

/// Returns an iterator over block numbers from `start` to `end` inclusive.
///
/// Returns an empty iterator if `start > end`.
fn block_range(start: BlockNumber, end: BlockNumber) -> impl Iterator<Item = BlockNumber> {
    let start = start.as_u32();
    let end = end.as_u32();
    (start..=end).map(BlockNumber::from)
}

/// Drains completed proofs from the results in sequential block-number order,
/// marking each as proven in the database.
///
/// Does nothing if the next expected block in sequence has not been proven.
async fn drain_sequential_results(
    db: &Db,
    results: &mut BTreeSet<BlockNumber>,
    latest_proven: &mut BlockNumber,
) -> Result<(), ProofSchedulerError> {
    loop {
        let next = latest_proven.child();
        if !results.remove(&next) {
            break;
        }
        db.mark_block_proven(next)
            .await
            .map_err(ProofSchedulerError::MarkBlockProvenFailed)?;
        info!(target: COMPONENT, block_num = %next, "Block marked as proven");
        *latest_proven = next;
    }
    Ok(())
}

// PROVE BLOCK
// ================================================================================================

/// Proves a single block, saves the proof to the block store, and returns the block number.
///
/// This function encapsulates the full lifecycle of a single proof job: loading inputs from the
/// DB, invoking the prover (with a timeout), and persisting the proof to disk.
///
/// The caller is responsible for marking the block as proven in the DB.
#[instrument(target = COMPONENT, name = "proof_scheduler.prove_and_save", skip_all, fields(%block_num))]
async fn prove_and_save(
    db: &Db,
    block_prover: &BlockProver,
    block_store: &BlockStore,
    block_num: BlockNumber,
) -> anyhow::Result<BlockNumber> {
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if attempts > 10 {
            anyhow::bail!("Bailed after max attempts")
        }
        // Prove block with timeout.
        let proof = match tokio::time::timeout(
            BLOCK_PROVE_TIMEOUT,
            prove_block(db, block_prover, block_num),
        )
        .await
        {
            Ok(Ok(proof)) => proof,
            Ok(Err(ProveBlockError::Fatal(err))) => anyhow::bail!("Fatal error: {err}"),
            Ok(Err(ProveBlockError::Transient(err))) => {
                error!("Transient error proving block {block_num}: {err}");
                continue;
            },
            Err(_elapsed) => {
                error!("Timed out proving block {block_num}");
                continue;
            },
        };

        // Save proof to the block store.
        block_store.save_proof(block_num, &proof.to_bytes()).await?;

        return Ok(block_num);
    }
}

/// Proves a single block by loading inputs from the DB and invoking the block prover.
async fn prove_block(
    db: &Db,
    block_prover: &BlockProver,
    block_num: BlockNumber,
) -> Result<BlockProof, ProveBlockError> {
    let request = db
        .select_block_proving_inputs(block_num)
        .await
        .map_err(ProveBlockError::from_db_error)?
        .ok_or_else(|| {
            ProveBlockError::Fatal(ProofSchedulerError::MissingProvingInputs(block_num))
        })?;

    let proof = block_prover
        .prove(request.tx_batches, request.block_inputs, &request.block_header)
        .await
        .map_err(ProveBlockError::from_prover_error)?;

    Ok(proof)
}

// PROVE BLOCK ERROR
// ================================================================================================

/// Errors that can occur during block proving.
#[derive(Debug)]
enum ProveBlockError {
    /// An irrecoverable error that should cause node shutdown.
    Fatal(ProofSchedulerError),
    /// A transient error (DB read, prover failure). The outer loop will retry.
    Transient(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl ProveBlockError {
    fn from_db_error(err: DatabaseError) -> Self {
        match err {
            DatabaseError::DeserializationError(err) => {
                Self::Fatal(ProofSchedulerError::DeserializationFailed(err))
            },
            _ => Self::Transient(err.into()),
        }
    }

    fn from_prover_error(err: StoreProverError) -> Self {
        match err {
            StoreProverError::RemoteProvingFailed(RemoteProverClientError::InvalidEndpoint(
                uri,
            )) => Self::Fatal(ProofSchedulerError::InvalidProverEndpoint(uri)),
            _ => Self::Transient(err.into()),
        }
    }
}
