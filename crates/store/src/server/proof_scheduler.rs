//! Background task that drives deferred block proving.
//!
//! The [`ProofScheduler`] is spawned as an internal Store task. It:
//!
//! 1. On startup, queries the DB for all unproven blocks (handles restart recovery).
//! 2. Listens on a [`tokio::sync::Notify`] for newly committed blocks.
//! 3. Proves blocks concurrently, but resolves completions in FIFO order via [`FuturesOrdered`].
//!    This ensures the ancestor rule: a block's proof is only persisted after all ancestor proofs
//!    have been persisted.
//! 4. Each proving future includes retry logic with exponential backoff and an overall timeout.
//! 5. On fatal errors (e.g. deserialization failures, timeout exhaustion), the future resolves with
//!    an error. The scheduler logs it and continues — the block will be retried on the next
//!    iteration.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesOrdered;
use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_protocol::block::{BlockNumber, BlockProof};
use miden_protocol::utils::{Deserializable, Serializable};
use tokio::sync::Notify;
use tracing::{error, info, instrument, warn};

use crate::COMPONENT;
use crate::db::Db;
use crate::server::block_prover_client::BlockProver;

// CONSTANTS
// ================================================================================================

/// Initial retry delay on proving failure.
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Maximum retry delay (caps the exponential backoff).
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// Overall timeout for proving a single block (including all retries).
const BLOCK_PROVE_TIMEOUT: Duration = Duration::from_secs(120);

// PROOF SCHEDULER
// ================================================================================================

/// Handle returned when spawning the proof scheduler, used to notify it of new blocks.
#[derive(Clone)]
pub struct ProofSchedulerHandle {
    notify: Arc<Notify>,
}

impl ProofSchedulerHandle {
    /// Notify the scheduler that a new block has been committed and may need proving.
    pub fn notify_block_committed(&self) {
        self.notify.notify_one();
    }
}

/// Spawns the proof scheduler as a background tokio task.
///
/// Returns a [`ProofSchedulerHandle`] that should be used to notify the scheduler when new
/// blocks are committed.
pub fn spawn(db: Arc<Db>, block_prover: Arc<BlockProver>) -> ProofSchedulerHandle {
    let notify = Arc::new(Notify::new());
    let handle = ProofSchedulerHandle { notify: Arc::clone(&notify) };

    tokio::spawn(run(db, block_prover, notify));

    handle
}

/// Main loop of the proof scheduler.
///
/// Uses [`FuturesOrdered`] to run proving concurrently while resolving completions in block
/// order. This provides natural backpressure and ensures proofs are persisted sequentially.
#[instrument(target = COMPONENT, name = "proof_scheduler", skip_all)]
async fn run(db: Arc<Db>, block_prover: Arc<BlockProver>, notify: Arc<Notify>) {
    info!(target: COMPONENT, "Proof scheduler started");

    loop {
        // Query all unproven blocks. This handles both startup recovery and new blocks.
        let unproven_blocks = match db.select_unproven_blocks().await {
            Ok(blocks) => blocks,
            Err(err) => {
                error!(target: COMPONENT, %err, "Failed to query unproven blocks, retrying");
                tokio::time::sleep(INITIAL_RETRY_DELAY).await;
                continue;
            },
        };

        // Wait for notify if there are no unproven blocks.
        if unproven_blocks.is_empty() {
            notify.notified().await;
            continue;
        }

        // Construct proving jobs and drain results in order.
        // On any failure we break immediately — dropping remaining futures cancels them.
        // The outer loop will re-query unproven blocks and restart the sequence, ensuring
        // we never persist a proof while an ancestor block is still unproven.
        let mut proving_futures = order_proving_jobs(&db, &block_prover, &unproven_blocks);
        while let Some((block_num, result)) = proving_futures.next().await {
            match result {
                Ok(proof) => persist_proof(&db, block_num, &proof).await,
                Err(err) => {
                    error!(
                        target: COMPONENT,
                        %block_num,
                        ?err,
                        "Block proving failed, abandoning batch and retrying next iteration"
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
    impl std::future::Future<Output = (BlockNumber, Result<BlockProof, ProveBlockError>)>,
> {
    let mut futures = FuturesOrdered::new();
    for &block_num in unproven_blocks {
        let db = Arc::clone(db);
        let block_prover = Arc::clone(block_prover);
        futures.push_back(async move {
            let result = tokio::time::timeout(
                BLOCK_PROVE_TIMEOUT,
                prove_block(&db, &block_prover, block_num),
            )
            .await;

            match result {
                Ok(proof) => (block_num, proof),
                Err(elapsed) => {
                    error!(
                        target: COMPONENT,
                        %block_num,
                        "Block proving timed out after {:?}",
                        elapsed,
                    );
                    (block_num, Err(ProveBlockError::Timeout))
                },
            }
        });
    }
    futures
}

/// Persists a proven block proof to the DB. Logs on success or failure.
async fn persist_proof(db: &Db, block_num: BlockNumber, proof: &BlockProof) {
    match db.insert_block_proof(block_num, proof).await {
        Ok(()) => {
            info!(
                target: COMPONENT,
                %block_num,
                proof_size = proof.to_bytes().len(),
                "Block proof persisted"
            );
        },
        Err(err) => {
            error!(
                target: COMPONENT,
                %block_num,
                %err,
                "Failed to persist block proof"
            );
        },
    }
}

// PROVE BLOCK
// ================================================================================================

/// Errors that can occur during block proving.
#[derive(Debug)]
enum ProveBlockError {
    /// The proving inputs were not found in the database.
    MissingProvingInputs,
    /// The proving inputs could not be deserialized.
    DeserializationFailed,
    /// The overall proving timeout was exceeded.
    Timeout,
}

/// Proves a single block, retrying with exponential backoff on transient failures.
///
/// Returns the proof on success, or a fatal error if proving cannot succeed (missing or
/// corrupt proving inputs).
///
/// This function is designed to be run as a future inside [`FuturesOrdered`]. Transient
/// errors (DB reads, prover failures) are retried internally. Only fatal errors are returned.
async fn prove_block(
    db: &Db,
    block_prover: &BlockProver,
    block_num: BlockNumber,
) -> Result<BlockProof, ProveBlockError> {
    // Load and deserialize proving inputs (with retries for transient DB errors).
    let request = load_proving_inputs(db, block_num).await?;

    // Prove the block (with retries for transient prover errors).
    prove_with_retries(block_prover, block_num, request).await
}

/// Loads and deserializes proving inputs from the DB, retrying on transient DB errors.
async fn load_proving_inputs(
    db: &Db,
    block_num: BlockNumber,
) -> Result<BlockProofRequest, ProveBlockError> {
    let mut retry_delay = INITIAL_RETRY_DELAY;

    loop {
        match db.select_block_proving_inputs(block_num).await {
            Ok(Some(bytes)) => {
                return BlockProofRequest::read_from_bytes(&bytes[..]).map_err(|err| {
                    error!(
                        target: COMPONENT,
                        %block_num,
                        %err,
                        "Failed to deserialize proving inputs"
                    );
                    ProveBlockError::DeserializationFailed
                });
            },
            Ok(None) => {
                error!(
                    target: COMPONENT,
                    %block_num,
                    "No proving inputs found for unproven block"
                );
                return Err(ProveBlockError::MissingProvingInputs);
            },
            Err(err) => {
                warn!(
                    target: COMPONENT,
                    %block_num,
                    %err,
                    ?retry_delay,
                    "Failed to load proving inputs, retrying"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
            },
        }
    }
}

/// Calls the block prover, retrying with exponential backoff on failure.
async fn prove_with_retries(
    block_prover: &BlockProver,
    block_num: BlockNumber,
    request: BlockProofRequest,
) -> Result<BlockProof, ProveBlockError> {
    let mut retry_delay = INITIAL_RETRY_DELAY;

    // The proving inputs must be re-usable across retries. Since `BlockProver::prove` takes
    // ownership, we serialize once and re-deserialize on each retry attempt.
    let request_bytes = request.to_bytes();

    // First attempt uses the already-deserialized request.
    match block_prover
        .prove(request.tx_batches, request.block_inputs, &request.block_header)
        .await
    {
        Ok(proof) => return Ok(proof),
        Err(err) => {
            warn!(
                target: COMPONENT,
                %block_num,
                %err,
                ?retry_delay,
                "Block proving failed, retrying"
            );
            tokio::time::sleep(retry_delay).await;
            retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
        },
    }

    // Subsequent retries re-deserialize from bytes.
    loop {
        let request = BlockProofRequest::read_from_bytes(&request_bytes[..]).map_err(|err| {
            error!(
                target: COMPONENT,
                %block_num,
                %err,
                "Failed to re-deserialize proving inputs during retry"
            );
            ProveBlockError::DeserializationFailed
        })?;

        match block_prover
            .prove(request.tx_batches, request.block_inputs, &request.block_header)
            .await
        {
            Ok(proof) => return Ok(proof),
            Err(err) => {
                warn!(
                    target: COMPONENT,
                    %block_num,
                    %err,
                    ?retry_delay,
                    "Block proving failed, retrying"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
            },
        }
    }
}
