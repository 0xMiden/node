use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use futures::TryFutureExt;
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_store::state::State;
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::{ErrorSpanExt, miden_instrument, miden_span_record};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{BatchId, ProposedBatch, ProvenBatch};
use miden_protocol::transaction::TransactionId;
use miden_remote_prover_client::RemoteBatchProver;
use miden_tx_batch::{BatchExecutor, LocalBatchProver};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{Instrument, Span};
use url::Url;

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{BuildBatchError, StoreError};
use crate::mempool::SharedMempool;
use crate::{COMPONENT, LOG_TARGET};

// BATCH BUILDER
// ================================================================================================

/// Builds [`ProvenBatch`] from sets of transactions.
///
/// Transaction sets are pulled from the mempool dynamically, and passed to a pool of provers for
/// proof generation. Full batches are built immediately; partial batches are delayed briefly to
/// give more transactions time to arrive.
pub struct BatchBuilder {
    /// Batch building jobs currently running.
    active_jobs: JoinSet<Result<(), BuildBatchError>>,
    num_workers: NonZeroUsize,
    intervals: BatchIntervals,
    /// The batch prover to use.
    ///
    /// If not provided, a local batch prover is used.
    batch_prover: BatchProver,
    store: Arc<State>,
}

pub(crate) struct BatchIntervals {
    /// Maximum time between spawned batch jobs before an any-size batch is attempted.
    max_batch_interval: Duration,
    /// How often the scheduler wakes to check whether a full batch can be spawned.
    full_batch_check_interval: Duration,
}

impl BatchIntervals {
    const MIN_SCHEDULER_INTERVAL: Duration = Duration::from_millis(50);

    /// Derives batch scheduler intervals from the block and legacy batch intervals.
    ///
    /// Full batches are produced as often as possible, but a batch is attempted at
    /// least every `batch_interval` if traffic is low.
    pub(crate) fn derive_from(block_interval: Duration, batch_interval: Duration) -> Self {
        let max_batch_interval = batch_interval.max(Self::MIN_SCHEDULER_INTERVAL);
        let full_batch_check_interval = (block_interval / 10).max(Self::MIN_SCHEDULER_INTERVAL);

        BatchIntervals {
            max_batch_interval,
            full_batch_check_interval,
        }
    }
}

impl BatchBuilder {
    /// Creates a new [`BatchBuilder`] with the given batch prover URL and maximum concurrent batch
    /// building workers.
    ///
    /// If no batch prover URL is provided, a local batch prover is used instead.
    pub fn new(
        store: Arc<State>,
        num_workers: NonZeroUsize,
        batch_prover_url: Option<Url>,
        intervals: BatchIntervals,
    ) -> Self {
        let batch_prover = batch_prover_url.map_or(BatchProver::local(), BatchProver::remote);

        Self {
            active_jobs: JoinSet::new(),
            num_workers,
            intervals,
            batch_prover,
            store,
        }
    }

    /// Starts the [`BatchBuilder`], creating and proving batches dynamically.
    ///
    /// Full batches are spawned on each check and job completion. A batch of any size is attempted
    /// when no batch has been spawned for the maximum batch interval.
    pub async fn run(mut self, mempool: SharedMempool) -> anyhow::Result<()> {
        let mut last_spawn = Instant::now();
        let mut full_batch_check = tokio::time::interval(self.intervals.full_batch_check_interval);
        full_batch_check.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            // Force a batch attempt after the maximum interval, even if it is partial.
            let force_at = tokio::time::sleep_until(last_spawn + self.intervals.max_batch_interval);
            let has_available_worker = self.has_available_worker();
            let has_active_job = !self.active_jobs.is_empty();

            tokio::select! {
                _ = force_at => {
                    last_spawn = Instant::now();
                    if has_available_worker {
                        self.spawn_any_batch_job(mempool.clone())?;
                    }
                },
                result = self.active_jobs.join_next(), if has_active_job => {
                    Self::handle_job_result(result.expect("active job set is not empty"))?;
                },
                _ = full_batch_check.tick() => {},
            }

            while self.has_available_worker() && self.spawn_full_batch_job(mempool.clone())? {
                last_spawn = Instant::now();
            }
        }
    }

    #[miden_instrument(
        parent = None,
        target = COMPONENT,
        name = "batch_builder.build_batch",
        skip_all,
    )]
    fn build_batch(&mut self, mempool: SharedMempool, batch: SelectedBatch) {
        miden_span_record!(
            workers.active = self.active_jobs.len(),
            workers.capacity = self.num_workers.get(),
        );

        let telemetry = batch.telemetry();
        miden_span_record!(
            batch.id = %telemetry.batch_id,
            transactions.count = telemetry.transactions_count,
            transactions.ids = ?telemetry.transaction_ids,
            transactions.input_notes.count = telemetry.input_notes_count,
            transactions.output_notes.count = telemetry.output_notes_count,
            transactions.unauthenticated_notes.count = telemetry.unauthenticated_notes_count,
        );
        let job = BatchJob {
            store: self.store.clone(),
            mempool,
            batch_prover: self.batch_prover.clone(),
        };

        self.active_jobs.spawn(
            async move { job.build_batch(batch).await }.instrument(tracing::Span::current()),
        );
    }

    fn spawn_full_batch_job(&mut self, mempool: SharedMempool) -> Result<bool, BuildBatchError> {
        let Some(batch) = Self::select_full_batch(&mempool)? else {
            return Ok(false);
        };

        self.build_batch(mempool, batch);
        Ok(true)
    }

    fn spawn_any_batch_job(&mut self, mempool: SharedMempool) -> Result<bool, BuildBatchError> {
        let Some(batch) = Self::select_any_batch(&mempool)? else {
            return Ok(false);
        };

        self.build_batch(mempool, batch);
        Ok(true)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.select_full_batch",
        skip_all,
    )]
    fn select_full_batch(
        mempool: &SharedMempool,
    ) -> Result<Option<SelectedBatch>, BuildBatchError> {
        Ok(mempool.lock().map_err(BuildBatchError::MempoolPoisoned)?.select_full_batch())
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.select_any_batch",
        skip_all,
    )]
    fn select_any_batch(mempool: &SharedMempool) -> Result<Option<SelectedBatch>, BuildBatchError> {
        Ok(mempool.lock().map_err(BuildBatchError::MempoolPoisoned)?.select_any_batch())
    }

    fn has_available_worker(&self) -> bool {
        self.active_jobs.len() < self.num_workers.get()
    }

    fn handle_job_result(
        result: Result<Result<(), BuildBatchError>, JoinError>,
    ) -> Result<(), BuildBatchError> {
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err),
            Err(crash) => {
                tracing::error!(target: LOG_TARGET, message=%crash, "Batch worker pool panic'd");
                panic!("Batch worker pool panic: {crash}");
            },
        }
    }
}

// BATCH JOB
// ================================================================================================

/// Represents a single batch building job.
///
/// It is entirely self-contained and performs the full batch creation flow, from fetching the
/// selected batch's inputs up to and including submitting the results back to the [`Mempool`].
///
/// Recoverable errors are handled internally. Mempool poison is propagated as a fatal error.
struct BatchJob {
    store: Arc<State>,
    batch_prover: BatchProver,
    mempool: SharedMempool,
}

impl BatchJob {
    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.build_batch_job",
        skip_all,
        err,
    )]
    async fn build_batch(&self, batch: SelectedBatch) -> Result<(), BuildBatchError> {
        let batch_id = batch.id();

        let result = self
            .get_batch_inputs(batch)
            .and_then(|(txs, inputs)| Self::propose_batch(txs, inputs))
            .inspect_ok(|proposed| {
                let telemetry = proposed_batch_telemetry(proposed);
                miden_span_record!(
                    batch.expiration_height = %telemetry.expiration_height,
                    batch.account_updates.count = telemetry.account_updates_count,
                    batch.input_notes.count = telemetry.input_notes_count,
                    batch.output_notes.count = telemetry.output_notes_count,
                );
            })
            .and_then(|proposed| self.prove_batch(proposed))
            .and_then(|proven_batch| async { self.commit_batch(proven_batch) })
            // Handle errors by propagating the error to the root span and rolling back the batch.
            .inspect_err(|err| Span::current().set_error(err))
            .instrument(Span::current())
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(err @ BuildBatchError::MempoolPoisoned(_)) => Err(err),
            Err(_) => {
                self.rollback_batch(batch_id)?;
                Ok(())
            },
        }
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.get_batch_inputs",
        skip_all,
        err,
    )]
    async fn get_batch_inputs(
        &self,
        batch: SelectedBatch,
    ) -> Result<(SelectedBatch, BatchInputs), BuildBatchError> {
        let block_references = batch
            .transactions()
            .iter()
            .map(Deref::deref)
            .map(AuthenticatedTransaction::reference_block);
        let unauthenticated_notes = batch
            .transactions()
            .iter()
            .map(Deref::deref)
            .flat_map(AuthenticatedTransaction::unauthenticated_note_ids);

        self.store
            .get_batch_inputs(
                block_references.map(|(block_num, _)| block_num).collect(),
                unauthenticated_notes.collect(),
            )
            .await
            .map_err(StoreError::GetBatchInputsFailed)
            .map_err(BuildBatchError::FetchBatchInputsFailed)
            .map(|inputs| (batch, inputs))
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.propose_batch",
        skip_all,
        err,
    )]
    async fn propose_batch(
        selected: SelectedBatch,
        inputs: BatchInputs,
    ) -> Result<ProposedBatch, BuildBatchError> {
        let transactions = selected
            .into_transactions()
            .into_iter()
            .map(|tx| tx.proven_transaction())
            .collect();

        ProposedBatch::new(
            transactions,
            inputs.batch_reference_block_header,
            inputs.partial_block_chain,
            inputs.note_proofs,
            MIN_PROOF_SECURITY_LEVEL,
        )
        .map_err(BuildBatchError::ProposeBatchError)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.prove_batch",
        skip_all,
        err,
    )]
    async fn prove_batch(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<Arc<ProvenBatch>, BuildBatchError> {
        miden_span_record!(prover.kind = self.batch_prover.kind(),);

        let proven_batch = match &self.batch_prover {
            BatchProver::Remote(prover) => prover
                .prove(proposed_batch)
                .await
                .map_err(BuildBatchError::RemoteProverClientError),
            BatchProver::Local(prover) => {
                let prover = prover.clone();
                spawn_blocking_in_current_span(move || {
                    let executed_batch = BatchExecutor::new()
                        .execute(proposed_batch)
                        .map_err(BuildBatchError::ProveBatchError)?;
                    prover.prove(executed_batch).map_err(BuildBatchError::ProveBatchError)
                })
                .await
                .map_err(BuildBatchError::JoinError)?
            },
        }?;

        if proven_batch.proof_security_level() < MIN_PROOF_SECURITY_LEVEL {
            Err(BuildBatchError::SecurityLevelTooLow(
                proven_batch.proof_security_level(),
                MIN_PROOF_SECURITY_LEVEL,
            ))
        } else {
            Ok(Arc::new(proven_batch))
        }
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.commit_batch",
        skip_all,
    )]
    fn commit_batch(&self, batch: Arc<ProvenBatch>) -> Result<(), BuildBatchError> {
        self.mempool
            .lock()
            .map_err(BuildBatchError::MempoolPoisoned)?
            .commit_batch(batch);
        Ok(())
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.rollback_batch",
        skip_all,
    )]
    fn rollback_batch(&self, batch_id: BatchId) -> Result<(), BuildBatchError> {
        self.mempool
            .lock()
            .map_err(BuildBatchError::MempoolPoisoned)?
            .rollback_batch(batch_id);
        Ok(())
    }
}

// BATCH PROVER
// ================================================================================================

/// Represents a batch prover which can be either local or remote.
#[derive(Clone)]
enum BatchProver {
    Local(LocalBatchProver),
    Remote(RemoteBatchProver),
}

impl BatchProver {
    const fn kind(&self) -> &'static str {
        match self {
            BatchProver::Local(_) => "local",
            BatchProver::Remote(_) => "remote",
        }
    }

    fn local() -> Self {
        Self::Local(LocalBatchProver::new())
    }

    fn remote(endpoint: impl Into<String>) -> Self {
        Self::Remote(RemoteBatchProver::new(endpoint))
    }
}

// TELEMETRY
// ================================================================================================

struct SelectedBatchTelemetry {
    batch_id: BatchId,
    transactions_count: usize,
    transaction_ids: Vec<TransactionId>,
    input_notes_count: usize,
    output_notes_count: usize,
    unauthenticated_notes_count: usize,
}

impl SelectedBatch {
    fn telemetry(&self) -> SelectedBatchTelemetry {
        // Accumulate all telemetry based on transactions.
        let (tx_ids, input_notes_count, output_notes_count, unauth_notes_count) =
            self.transactions().iter().fold(
                (vec![], 0, 0, 0),
                |(
                    mut tx_ids,
                    mut input_notes_count,
                    mut output_notes_count,
                    mut unauth_notes_count,
                ),
                 tx| {
                    tx_ids.push(tx.id());
                    input_notes_count += tx.input_note_count();
                    output_notes_count += tx.output_note_count();
                    unauth_notes_count += tx.unauthenticated_note_ids().count();
                    (tx_ids, input_notes_count, output_notes_count, unauth_notes_count)
                },
            );
        SelectedBatchTelemetry {
            batch_id: self.id(),
            transactions_count: self.transactions().len(),
            transaction_ids: tx_ids,
            input_notes_count,
            output_notes_count,
            unauthenticated_notes_count: unauth_notes_count,
        }
    }
}

struct ProposedBatchTelemetry {
    expiration_height: miden_protocol::block::BlockNumber,
    account_updates_count: usize,
    input_notes_count: usize,
    output_notes_count: usize,
}

fn proposed_batch_telemetry(batch: &ProposedBatch) -> ProposedBatchTelemetry {
    ProposedBatchTelemetry {
        expiration_height: batch.batch_expiration_block_num(),
        account_updates_count: batch.account_updates().len(),
        input_notes_count: usize::from(batch.input_notes().num_notes()),
        output_notes_count: batch.output_notes().len(),
    }
}
