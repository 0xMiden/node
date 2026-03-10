//! Background task that drives deferred block proving.
//!
//! The [`proof_scheduler`] is spawned as an internal Store task. It:
//!
//! 1. Tracks `chain_tip` via a [`watch::Receiver<BlockNumber>`] and `latest_proven_block` locally.
//! 2. Maintains up to `max_concurrent_proofs` in-flight proving jobs via a [`JoinSet`].
//! 3. Marks blocks as proven in the database **sequentially** — a block is only marked after all
//!    its ancestors have been marked.
//! 4. On transient errors (DB reads, prover failures, timeouts), the failed block is retried
//!    internally within its proving task.
//! 5. On fatal errors (e.g. deserialization failures, missing proving inputs), the scheduler
//!    returns the error to the caller for node shutdown.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_protocol::block::{BlockNumber, BlockProof};
use miden_protocol::utils::Serializable;
use miden_remote_prover_client::RemoteProverClientError;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::blocks::BlockStore;
use crate::db::Db;
use crate::errors::{DatabaseError, ProofSchedulerError};
use crate::server::block_prover_client::{BlockProver, StoreProverError};

// CONSTANTS
// ================================================================================================

/// Overall timeout for proving a single block.
const BLOCK_PROVE_TIMEOUT: Duration = Duration::from_mins(4);

/// Default maximum number of blocks being proven concurrently.
pub const DEFAULT_MAX_CONCURRENT_PROOFS: usize = 8;

/// A wrapper around [`JoinSet`] whose `join_next` returns [`std::future::pending`] when empty
/// instead of `None`, making it safe to use directly in `tokio::select!` without a special case.
struct ProofTaskJoinSet(JoinSet<anyhow::Result<BlockNumber>>);

impl ProofTaskJoinSet {
    fn new() -> Self {
        Self(JoinSet::new())
    }

    fn spawn(
        &mut self,
        db: &Arc<Db>,
        block_prover: &Arc<BlockProver>,
        block_store: &Arc<BlockStore>,
        block_num: BlockNumber,
    ) {
        let db = Arc::clone(db);
        let block_prover = Arc::clone(block_prover);
        let block_store = Arc::clone(block_store);
        self.0.spawn(
            async move { prove_and_save(&db, &block_prover, &block_store, block_num).await },
        );
    }

    /// Returns the result of the next completed task, or pends forever if the set is empty.
    async fn join_next(&mut self) -> anyhow::Result<BlockNumber> {
        if self.0.is_empty() {
            std::future::pending().await
        } else {
            self.0
                .join_next()
                .await
                .expect("join set is not empty")
                .context("proving task panicked")
                .flatten()
        }
    }
}

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
    max_concurrent_proofs: usize,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(run(
        db,
        block_prover,
        block_store,
        chain_tip_rx,
        latest_proven_block,
        max_concurrent_proofs,
    ))
}

/// Main loop of the proof scheduler.
///
/// Maintains a pool of concurrent proving jobs via [`JoinSet`], fills them up to
/// `max_concurrent_proofs`, and drains completed results in block-number order.
///
/// Returns `Err` on irrecoverable errors (missing/corrupt proving inputs, DB write failures).
/// Transient errors are retried internally.
async fn run(
    db: Arc<Db>,
    block_prover: Arc<BlockProver>,
    block_store: Arc<BlockStore>,
    mut chain_tip_rx: watch::Receiver<BlockNumber>,
    latest_proven_block: BlockNumber,
    max_concurrent_proofs: usize,
) -> anyhow::Result<()> {
    info!(target: COMPONENT, %latest_proven_block, "Proof scheduler started");

    // The latest block that has been sequentially marked as proven in the DB.
    let mut latest_complete = latest_proven_block;
    // The current chain tip as observed from the watch channel.
    let mut chain_tip = *chain_tip_rx.borrow_and_update();
    // In-flight proving tasks.
    let mut join_set = ProofTaskJoinSet::new();
    // Block numbers currently being proven.
    let mut inflight: BTreeSet<BlockNumber> = BTreeSet::new();
    // The next block number to schedule for proving.
    let mut next_to_schedule = latest_complete.child();

    loop {
        // Fill the job pool up to capacity from the next unscheduled blocks.
        while inflight.len() < max_concurrent_proofs
            && next_to_schedule.as_u32() <= chain_tip.as_u32()
        {
            let scheduled = next_to_schedule;
            inflight.insert(scheduled);

            join_set.spawn(&db, &block_prover, &block_store, scheduled);
            next_to_schedule = scheduled.child();
        }

        // Wait for either a job to complete or the chain tip to advance.
        tokio::select! {
            // Proving task completed.
            result = join_set.join_next() => {
                let block_num = result?;
                info!(target=COMPONENT, block.number=%block_num, "Block proof completed");
                inflight.remove(&block_num);
            },

            // New chain tip received.
            result = chain_tip_rx.changed() => {
                if result.is_err() {
                    info!(target: COMPONENT, "Chain tip channel closed, proof scheduler exiting");
                    return Ok(());
                }
                chain_tip = *chain_tip_rx.borrow();
            },
        }

        // Mark completed proofs as proven sequentially.
        // Find the lowest in-flight block.
        let lowest_in_flight = inflight.first().copied().unwrap_or(next_to_schedule);
        // Mark all sequentially proven blocks as completed.
        while latest_complete.child().as_u32() < lowest_in_flight.as_u32() {
            latest_complete = latest_complete.child();
            db.mark_block_proven(latest_complete)
                .await
                .map_err(ProofSchedulerError::MarkBlockProvenFailed)?;
            info!(target=COMPONENT, block.number=%latest_complete, "Block marked as proven");
        }
    }
}

// PROVE BLOCK
// ================================================================================================

/// Proves a single block, saves the proof to the block store, and returns the block number.
///
/// This function encapsulates the full lifecycle of a single proof job: loading inputs from the
/// DB, invoking the prover (with a timeout), and persisting the proof to disk.
///
/// The caller is responsible for marking the block as proven in the DB.
#[instrument(target = COMPONENT, name = "prove_block", skip_all, fields(%block_num), err)]
async fn prove_and_save(
    db: &Db,
    block_prover: &BlockProver,
    block_store: &BlockStore,
    block_num: BlockNumber,
) -> anyhow::Result<BlockNumber> {
    const MAX_RETRIES: u32 = 10;

    for _ in 0..MAX_RETRIES {
        match tokio::time::timeout(BLOCK_PROVE_TIMEOUT, prove_block(db, block_prover, block_num))
            .await
        {
            Ok(Ok(proof)) => {
                save_block(block_store, block_num, &proof).await?;
                return Ok(block_num);
            },
            Ok(Err(ProveBlockError::Fatal(err))) => anyhow::bail!("Fatal error: {err}"),
            Ok(Err(ProveBlockError::Transient(_))) | Err(_) => {
                // Errors are logged via the span.
            },
        }
    }

    anyhow::bail!("maximum retries ({MAX_RETRIES}) exceeded");
}

/// Proves a single block by loading inputs from the DB and invoking the block prover.
///
/// Records `block_commitment` on `parent_span` once the block header is available.
#[instrument(target = COMPONENT, name = "prove_block.prove", skip_all, fields(%block_num), err)]
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

/// Saves a block proof to the block store.
#[instrument(target = COMPONENT, name = "prove_block.save", skip_all, fields(%block_num), err)]
async fn save_block(
    block_store: &BlockStore,
    block_num: BlockNumber,
    proof: &BlockProof,
) -> anyhow::Result<()> {
    block_store.save_proof(block_num, &proof.to_bytes()).await?;
    Ok(())
}

// PROVE BLOCK ERROR
// ================================================================================================

/// Errors that can occur during block proving.
#[derive(Debug, Error)]
enum ProveBlockError {
    /// An irrecoverable error that should cause node shutdown.
    #[error("fatal error")]
    Fatal(#[source] ProofSchedulerError),
    /// A transient error (DB read, prover failure). The outer loop will retry.
    #[error("transient error: {0}")]
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
