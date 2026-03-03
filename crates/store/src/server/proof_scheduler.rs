//! Background task that drives deferred block proving.
//!
//! The [`ProofScheduler`] is spawned as an internal Store task. It:
//!
//! 1. On startup, queries the DB for all unproven blocks (handles restart recovery).
//! 2. Listens on a [`tokio::sync::Notify`] for newly committed blocks.
//! 3. Proves blocks concurrently, but resolves completions in FIFO order via [`FuturesOrdered`].
//!    This ensures the ancestor rule: a block's proof is only persisted after all ancestor proofs
//!    have been persisted.
//! 4. On transient errors (DB reads, prover failures, timeouts), the scheduler abandons the current
//!    batch, re-queries unproven blocks, and retries from scratch.
//! 5. On fatal errors (e.g. deserialization failures, missing proving inputs), the scheduler
//!    returns the error to the caller for node shutdown.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesOrdered;
use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_protocol::block::{BlockNumber, BlockProof};
use miden_protocol::utils::{Deserializable, Serializable};
use miden_remote_prover_client::RemoteProverClientError;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
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

/// Maximum number of unproven blocks to process in a single batch.
const MAX_PROVING_BATCH_SIZE: i64 = 16;

// PROOF SCHEDULER
// ================================================================================================

/// Handle returned when spawning the proof scheduler, used to notify it of new blocks.
#[derive(Clone)]
pub struct ProofSchedulerHandle {
    notify: Arc<Notify>,
}

impl ProofSchedulerHandle {
    /// Notify the scheduler that a new block has been committed and may need proving.
    #[instrument(target = COMPONENT, name = "proof_scheduler.notify", skip_all)]
    pub fn notify_block_committed(&self) {
        self.notify.notify_one();
    }
}

/// Spawns the proof scheduler as a background tokio task.
///
/// Returns a [`ProofSchedulerHandle`] that should be used to notify the scheduler when new
/// blocks are committed, and a [`JoinHandle`] that resolves when the scheduler encounters a
/// fatal error or completes unexpectedly.
pub fn spawn(
    db: Arc<Db>,
    block_prover: Arc<BlockProver>,
    block_store: Arc<BlockStore>,
) -> (ProofSchedulerHandle, JoinHandle<Result<(), ProofSchedulerError>>) {
    let notify = Arc::new(Notify::new());
    let handle = ProofSchedulerHandle { notify: Arc::clone(&notify) };

    let join_handle = tokio::spawn(run(db, block_prover, block_store, notify));

    (handle, join_handle)
}

/// Main loop of the proof scheduler.
///
/// Uses [`FuturesOrdered`] to run proving concurrently while resolving completions in block
/// order. This provides natural backpressure and ensures proofs are persisted sequentially.
///
/// Returns `Err` on irrecoverable errors (missing/corrupt proving inputs, DB write failures).
/// Transient errors are retried internally.
async fn run(
    db: Arc<Db>,
    block_prover: Arc<BlockProver>,
    block_store: Arc<BlockStore>,
    notify: Arc<Notify>,
) -> Result<(), ProofSchedulerError> {
    info!(target: COMPONENT, "Proof scheduler started");

    loop {
        // Capture the notify permit before retrieving unproven blocks from the database.
        // This ensures that a notify fired between the database query and the wait on the permit
        // will be captured; meaning we don't block unnecessarily until the next notify.
        let notified = notify.notified();

        // Query all unproven blocks. This handles both startup recovery and new blocks.
        let unproven_blocks = match db.select_unproven_blocks(MAX_PROVING_BATCH_SIZE).await {
            Ok(blocks) => blocks,
            Err(err) => {
                error!(target: COMPONENT, %err, "Failed to query unproven blocks, retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            },
        };

        // Wait for notify if there are no unproven blocks.
        if unproven_blocks.is_empty() {
            notified.await;
            continue;
        }

        // Construct proving jobs and drain results in order.
        // On any failure we break immediately — dropping remaining futures cancels them.
        // The outer loop will re-query unproven blocks and restart the sequence, ensuring
        // we never persist a proof while an ancestor block is still unproven.
        let mut proving_futures = order_proving_jobs(&db, &block_prover, &unproven_blocks);
        while let Some(timeout_result) = proving_futures.next().await {
            match timeout_result {
                // Save proof to file, then mark as proven in DB.
                Ok((block_num, proof)) => {
                    block_store
                        .save_proof(block_num, &proof.to_bytes())
                        .await
                        .map_err(ProofSchedulerError::PersistProofFailed)?;
                    db.mark_block_proven(block_num)
                        .await
                        .map_err(ProofSchedulerError::MarkBlockProvenFailed)?;
                },

                // Abort on fatal errors.
                Err(ProveBlockError::Fatal(err)) => return Err(err),

                // Log transient errors and restart proof scheduler loop.
                Err(ProveBlockError::Transient(err)) => {
                    error!(
                        target: COMPONENT,
                        %err,
                        "Block proving failed, abandoning batch and retrying next iteration"
                    );
                    break;
                },
                Err(ProveBlockError::Timeout) => {
                    error!(
                        target: COMPONENT,
                        "Block proving timed out, abandoning batch and retrying next iteration"
                    );
                    break;
                },
            }
        }
    }
}

/// Submits all unproven blocks into a [`FuturesOrdered`]. Each future runs the full
/// prove-with-retries pipeline concurrently, but completions are polled in submission
/// (i.e. block) order.
fn order_proving_jobs(
    db: &Arc<Db>,
    block_prover: &Arc<BlockProver>,
    unproven_blocks: &[BlockNumber],
) -> FuturesOrdered<
    impl std::future::Future<Output = Result<(BlockNumber, BlockProof), ProveBlockError>>,
> {
    let mut futures = FuturesOrdered::new();
    for &block_num in unproven_blocks {
        // Clone the resources for each future.
        let db = Arc::clone(db);
        let block_prover = Arc::clone(block_prover);
        // Define the future.
        let fut = async move {
            // Prove block with timeout.
            let timeout_result = tokio::time::timeout(
                BLOCK_PROVE_TIMEOUT,
                prove_block(&db, &block_prover, block_num),
            )
            .await;
            // Handle proving result.
            match timeout_result {
                Ok(proof_result) => proof_result.map(|proof| (block_num, proof)),
                Err(_elapsed) => Err(ProveBlockError::Timeout),
            }
        };
        futures.push_back(fut);
    }
    futures
}

// PROVE BLOCK
// ================================================================================================

/// Proves a single block.
///
/// Loads proving inputs from the DB, deserializes them, and invokes the block prover.
/// blocks.
#[instrument(target = COMPONENT, name = "proof_scheduler.prove_block", skip_all, fields(%block_num))]
async fn prove_block(
    db: &Db,
    block_prover: &BlockProver,
    block_num: BlockNumber,
) -> Result<BlockProof, ProveBlockError> {
    // Load proving inputs from the DB.
    // All committed blocks should have inputs apart from the genesis block, which should
    // never be queried by this function.
    let bytes = db
        .select_block_proving_inputs(block_num)
        .await
        .map_err(ProveBlockError::from)?
        .ok_or_else(|| {
            ProveBlockError::Fatal(ProofSchedulerError::MissingProvingInputs(block_num))
        })?;

    // Deserialize proving inputs.
    let request = BlockProofRequest::read_from_bytes(&bytes[..])
        .map_err(|err| ProveBlockError::Fatal(ProofSchedulerError::DeserializationFailed(err)))?;

    // Prove the block.
    let proof = block_prover
        .prove(request.tx_batches, request.block_inputs, &request.block_header)
        .await
        .map_err(ProveBlockError::from)?;

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
    /// The overall proving timeout was exceeded. Retriable on next iteration.
    Timeout,
}

impl From<DatabaseError> for ProveBlockError {
    fn from(err: DatabaseError) -> Self {
        match err {
            DatabaseError::DeserializationError(err) => {
                Self::Fatal(ProofSchedulerError::DeserializationFailed(err))
            },
            _ => Self::Transient(err.into()),
        }
    }
}

impl From<StoreProverError> for ProveBlockError {
    fn from(err: StoreProverError) -> Self {
        match err {
            StoreProverError::RemoteProvingFailed(RemoteProverClientError::InvalidEndpoint(
                uri,
            )) => Self::Fatal(ProofSchedulerError::InvalidProverEndpoint(uri)),
            _ => Self::Transient(err.into()),
        }
    }
}
