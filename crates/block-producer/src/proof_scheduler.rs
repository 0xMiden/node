//! Background task that drives deferred block proving.
//!
//! The scheduler:
//!
//! 1. Tracks `chain_tip` via a [`watch::Receiver<BlockNumber>`].
//! 2. Maintains up to `max_concurrent_proofs` in-flight proving jobs via a [`JoinSet`].
//! 3. Blocks may be proven out of order since proving jobs run concurrently. Completed proofs are
//!    buffered and committed to the block store in ascending block-number order.
//! 4. On transient errors (prover failures, timeouts), the failed block is retried internally
//!    within its proving task, subject to an overall per-block time budget.
//! 5. On fatal errors (e.g. missing proving inputs files), the scheduler returns the error to the
//!    caller for node shutdown.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::BlockProofRequest;
use miden_node_store::state::{Finality, State};
use miden_node_utils::retry::{self, Retryable};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::block::{BlockNumber, BlockProof};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_remote_prover_client::RemoteProverClientError;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{Instrument, debug, info};

use crate::block_prover::{BlockProver, ProverError};
use crate::errors::ProofSchedulerError;
use crate::{COMPONENT, LOG_TARGET};

// CONSTANTS
// ================================================================================================

/// Timeout for a single block proof attempt (per-retry).
const BLOCK_PROVE_ATTEMPT_TIMEOUT: Duration = Duration::from_mins(4);

/// Overall timeout for proving a single block (across all retries).
const BLOCK_PROVE_OVERALL_TIMEOUT: Duration = Duration::from_mins(12);

/// Maximum number of proving attempts per block before giving up.
const MAX_PROVE_ATTEMPTS: u32 = 3;

/// Default maximum number of blocks being proven concurrently.
pub const DEFAULT_MAX_CONCURRENT_PROOFS: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// A wrapper around [`JoinSet`] whose `join_next` returns [`std::future::pending`] when empty
/// instead of `None`, making it safe to use directly in `tokio::select!` without a special case.
struct ProofTaskJoinSet(JoinSet<anyhow::Result<(BlockNumber, Vec<u8>)>>);

impl ProofTaskJoinSet {
    fn new() -> Self {
        Self(JoinSet::new())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Spawns a new task to prove a block.
    fn spawn(
        &mut self,
        state: &Arc<State>,
        block_prover: &Arc<BlockProver>,
        block_num: BlockNumber,
    ) {
        let state = Arc::clone(state);
        let block_prover = Arc::clone(block_prover);
        self.0.spawn(async move { prove_block(&state, &block_prover, block_num).await });
    }

    /// Returns the result of the next completed task, or pends forever if the set is empty.
    async fn join_next(&mut self) -> anyhow::Result<(BlockNumber, Vec<u8>)> {
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

/// Main loop of the proof scheduler.
///
/// Maintains a pool of concurrent proving jobs via [`JoinSet`], fills them up to
/// `max_concurrent_proofs`, and drains completed results.
///
/// Unproven blocks are discovered by comparing the proven tip against the chain tip: every block
/// in the range `(proven_tip, chain_tip]` has a proving inputs file in the block store.
///
/// Returns `Err` on irrecoverable errors (missing proving inputs, I/O failures).
/// Transient errors are retried internally.
pub(crate) async fn run(
    block_prover: Arc<BlockProver>,
    state: Arc<State>,
    mut chain_tip_rx: watch::Receiver<BlockNumber>,
    max_concurrent_proofs: NonZeroUsize,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    info!(target: LOG_TARGET, "Proof scheduler started");

    // In-flight proving tasks.
    let mut proving_tasks = ProofTaskJoinSet::new();

    // Next block number to schedule. Initialized from the proven tip's child so we skip
    // already-proven blocks on restart.
    let mut next_to_prove = state.chain_tip(Finality::Proven).await.child();

    // Completed proofs waiting to be committed in order.
    let mut pending: BTreeMap<BlockNumber, Vec<u8>> = BTreeMap::new();

    loop {
        // Schedule blocks up to chain_tip that haven't been scheduled yet.
        let chain_tip = *chain_tip_rx.borrow();
        while proving_tasks.len() < max_concurrent_proofs.get() && next_to_prove <= chain_tip {
            proving_tasks.spawn(&state, &block_prover, next_to_prove);
            next_to_prove = next_to_prove.child();
        }

        // Wait for either a job to complete or the chain tip to advance.
        tokio::select! {
            () = shutdown.cancelled() => {
                while !proving_tasks.is_empty() {
                    let (block_num, proof_bytes) = proving_tasks.join_next().await?;
                    pending.insert(block_num, proof_bytes);
                }
                return Ok(());
            },
            // Proving a block has completed - cache and commit the proof.
            proving_result = proving_tasks.join_next() => {
                let (block_num, proof_bytes) = proving_result?;
                pending.insert(block_num, proof_bytes);

                // Drain completed proofs in ascending order so the proven tip advances without
                // gaps.
                let mut next = state.chain_tip(Finality::Proven).await.child();
                while let Some(proof_bytes) = pending.remove(&next) {
                    state.apply_proof(next, proof_bytes).await?;
                    next = next.child();
                }
            },
            // New chain tip received - re-enter the scheduling loop on next iteration.
            result = chain_tip_rx.changed() => {
                if result.is_err() {
                    debug!(target: LOG_TARGET, "Chain tip channel closed, proof scheduler exiting");
                    return Ok(());
                }
            },
        }
    }
}

// PROVE BLOCK
// ================================================================================================

/// Proves a single block and returns the proof bytes on success.
#[miden_instrument(
    target = COMPONENT,
    name = "prove_block",
    skip_all,
    fields(
        block.number=block_num.as_u32(),
    ),
    err,
)]
async fn prove_block(
    state: &State,
    block_prover: &BlockProver,
    block_num: BlockNumber,
) -> anyhow::Result<(BlockNumber, Vec<u8>)> {
    tokio::time::timeout(BLOCK_PROVE_OVERALL_TIMEOUT, async {
        let mut attempt: u32 = 0;

        // Retry transient failures and per-attempt timeouts up to `MAX_PROVE_ATTEMPTS` times,
        // bailing out immediately on fatal errors. A timeout is mapped to a transient error so it
        // is retried like any other transient failure.
        let result = (|| {
            attempt += 1;
            let attempt_span = tracing::info_span!(
                target: COMPONENT,
                "prove_attempt",
                attempt,
                error = tracing::field::Empty,
                timed_out = tracing::field::Empty,
            );

            async move {
                let outcome = tokio::time::timeout(
                    BLOCK_PROVE_ATTEMPT_TIMEOUT,
                    generate_block_proof(state, block_prover, block_num),
                )
                .await;

                match outcome {
                    Ok(Ok(proof)) => Ok((block_num, proof.to_bytes())),
                    Ok(Err(err @ ProveBlockError::Fatal(_))) => Err(err),
                    Ok(Err(ProveBlockError::Transient(err))) => {
                        tracing::Span::current().record("error", tracing::field::display(&err));
                        Err(ProveBlockError::Transient(err))
                    },
                    Err(elapsed) => {
                        tracing::Span::current().record("timed_out", elapsed.to_string());
                        Err(ProveBlockError::Transient(Box::new(elapsed)))
                    },
                }
            }
            .instrument(attempt_span)
        })
        .retry(retry::constant(Duration::ZERO, Some((MAX_PROVE_ATTEMPTS - 1) as usize)))
        .when(|err| matches!(err, ProveBlockError::Transient(_)))
        .await;

        match result {
            Ok(proof) => Ok(proof),
            Err(ProveBlockError::Fatal(err)) => Err(err).context("fatal error"),
            Err(ProveBlockError::Transient(_)) => {
                anyhow::bail!("block {} failed after {attempt} attempts", block_num.as_u32())
            },
        }
    })
    .await
    .context(format!(
        "block proving overall timeout ({BLOCK_PROVE_OVERALL_TIMEOUT:?}) exceeded"
    ))?
}

/// Generates a block proof by loading inputs from the block store and invoking the block prover.
#[miden_instrument(
    target = COMPONENT,
    name = "prove_block.generate",
    skip_all,
    fields(
        block.number=block_num.as_u32(),
    ),
    err,
)]
async fn generate_block_proof(
    state: &State,
    block_prover: &BlockProver,
    block_num: BlockNumber,
) -> Result<BlockProof, ProveBlockError> {
    let bytes = state
        .load_proving_inputs(block_num)
        .await
        .map_err(|e| ProveBlockError::Transient(e.into()))?
        .ok_or_else(|| {
            ProveBlockError::Fatal(ProofSchedulerError::MissingProvingInputs(block_num))
        })?;

    let request = BlockProofRequest::read_from_bytes(&bytes)
        .map_err(|e| ProveBlockError::Fatal(ProofSchedulerError::DeserializationFailed(e)))?;

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
    /// A transient error (I/O, prover failure). The outer loop will retry.
    #[error("transient error: {0}")]
    Transient(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl ProveBlockError {
    fn from_prover_error(err: ProverError) -> Self {
        match err {
            ProverError::RemoteProvingFailed(RemoteProverClientError::InvalidEndpoint(uri)) => {
                Self::Fatal(ProofSchedulerError::InvalidProverEndpoint(uri))
            },
            _ => Self::Transient(err.into()),
        }
    }
}
