//! Background task that drives deferred block proving.
//!
//! The [`proof_scheduler`] is spawned as an internal Store task. It:
//!
//! 1. Tracks `chain_tip` via a [`watch::Receiver<BlockNumber>`] and `latest_proven_block` locally.
//! 2. Maintains up to `max_concurrent_proofs` in-flight proving jobs via a [`JoinSet`].
//! 3. Blocks may be proven out of order since proving jobs run concurrently. When a block is marked
//!    as proven, the database atomically advances the `proven_in_sequence` column for all blocks
//!    that now form a contiguous proven sequence from genesis.
//! 4. On transient errors (DB reads, prover failures, timeouts), the failed block is retried
//!    internally within its proving task.
//! 5. On fatal errors (e.g. deserialization failures, missing proving inputs), the scheduler
//!    returns the error to the caller for node shutdown.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_crypto::utils::Serializable;
use miden_protocol::block::{BlockNumber, BlockProof};
use miden_remote_prover_client::RemoteProverClientError;
use thiserror::Error;
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

/// Default maximum number of blocks being proven concurrently.
pub const DEFAULT_MAX_CONCURRENT_PROOFS: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// A wrapper around [`JoinSet`] whose `join_next` returns [`std::future::pending`] when empty
/// instead of `None`, making it safe to use directly in `tokio::select!` without a special case.
struct ProofTaskJoinSet(JoinSet<anyhow::Result<()>>);

impl ProofTaskJoinSet {
    fn new() -> Self {
        Self(JoinSet::new())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// Spawns a new task to prove a block.
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
        self.0
            .spawn(async move { prove_block(&db, &block_prover, &block_store, block_num).await });
    }

    /// Returns the result of the next completed task, or pends forever if the set is empty.
    async fn join_next(&mut self) -> anyhow::Result<()> {
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
/// The scheduler uses `chain_tip_rx` to learn about newly committed blocks and queries the DB
/// for unproven blocks to prove.
///
/// Returns a [`JoinHandle`] that resolves when the scheduler encounters a fatal error or
/// completes unexpectedly.
pub fn spawn(
    db: Arc<Db>,
    block_prover: Arc<BlockProver>,
    block_store: Arc<BlockStore>,
    chain_tip_rx: watch::Receiver<BlockNumber>,
    max_concurrent_proofs: NonZeroUsize,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(run(db, block_prover, block_store, chain_tip_rx, max_concurrent_proofs))
}

/// Main loop of the proof scheduler.
///
/// Maintains a pool of concurrent proving jobs via [`JoinSet`], fills them up to
/// `max_concurrent_proofs`, and drains completed results.
///
/// Unproven blocks are discovered by querying the database each iteration.
///
/// Returns `Err` on irrecoverable errors (missing/corrupt proving inputs, DB write failures).
/// Transient errors are retried internally.
async fn run(
    db: Arc<Db>,
    block_prover: Arc<BlockProver>,
    block_store: Arc<BlockStore>,
    mut chain_tip_rx: watch::Receiver<BlockNumber>,
    max_concurrent_proofs: NonZeroUsize,
) -> anyhow::Result<()> {
    info!(target: COMPONENT, "Proof scheduler started");

    // In-flight proving tasks.
    let mut join_set = ProofTaskJoinSet::new();

    // Highest block number that is in-flight or has been proven. Used to avoid re-querying
    // blocks we've already scheduled. Initialized from the in-sequence tip so we skip
    // already-proven blocks on restart.
    let mut highest_scheduled = db.select_latest_proven_in_sequence_block_num().await?;

    loop {
        // Query the DB for unproven blocks beyond what we've already scheduled.
        let capacity = max_concurrent_proofs.get() - join_set.len();
        if capacity > 0 {
            let unproven = db.select_unproven_blocks(highest_scheduled, capacity).await?;

            if let Some(&last) = unproven.last() {
                highest_scheduled = last;
            }

            for block_num in unproven {
                join_set.spawn(&db, &block_prover, &block_store, block_num);
            }
        }

        // Wait for either a job to complete or the chain tip to advance.
        tokio::select! {
            result = join_set.join_next() => {
                result?;
            },

            // New chain tip received — re-query for unproven blocks on next iteration.
            result = chain_tip_rx.changed() => {
                if result.is_err() {
                    info!(target: COMPONENT, "Chain tip channel closed, proof scheduler exiting");
                    return Ok(());
                }
            },
        }
    }
}

// PROVE BLOCK
// ================================================================================================

/// Proves a single block, saves the proof to the block store, marks the block as proven in the
/// DB, and advances the proven-in-sequence tip.
#[instrument(target = COMPONENT, name = "prove_block", skip_all, fields(block.number=block_num.as_u32()), err)]
async fn prove_block(
    db: &Db,
    block_prover: &BlockProver,
    block_store: &BlockStore,
    block_num: BlockNumber,
) -> anyhow::Result<()> {
    const MAX_RETRIES: u32 = 10;

    for _ in 0..MAX_RETRIES {
        match tokio::time::timeout(
            BLOCK_PROVE_TIMEOUT,
            generate_block_proof(db, block_prover, block_num),
        )
        .await
        {
            Ok(Ok(proof)) => {
                // Save the block proof to file.
                block_store.save_proof(block_num, &proof.to_bytes()).await?;

                // Mark the block as proven and advance the sequence in the database.
                let advanced_in_sequence = db.mark_proven_and_advance_sequence(block_num).await?;
                if let Some(&last) = advanced_in_sequence.last() {
                    info!(
                        target = COMPONENT,
                        block.number = %block_num,
                        proven_in_sequence_tip = %last,
                        "Block proven and in-sequence advanced",
                    );
                } else {
                    info!(target = COMPONENT, block.number = %block_num, "Block proven");
                }

                return Ok(());
            },
            Ok(Err(ProveBlockError::Fatal(err))) => Err(err).context("fatal error")?,
            Ok(Err(ProveBlockError::Transient(err))) => {
                error!(target: COMPONENT, %block_num, err = ?err, "transient error proving block, retrying");
            },
            Err(elapsed) => {
                error!(target: COMPONENT, %block_num, %elapsed, "block proving timed out, retrying");
            },
        }
    }

    anyhow::bail!("maximum retries ({MAX_RETRIES}) exceeded");
}

/// Generates a block proof by loading inputs from the DB and invoking the block prover.
///
/// Records `block_commitment` on `parent_span` once the block header is available.
#[instrument(target = COMPONENT, name = "prove_block.generate", skip_all, fields(block.number=block_num.as_u32()), err)]
async fn generate_block_proof(
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
