use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use futures::never::Never;
use futures::{FutureExt, TryFutureExt};
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{BatchId, ProposedBatch, ProvenBatch};
use miden_remote_prover_client::remote_prover::RemoteBatchProver;
use miden_tx_batch_prover::LocalBatchProver;
use rand::Rng;
use tokio::task::JoinSet;
use tokio::time;
use tracing::{Instrument, Span, instrument};
use url::Url;

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::BuildBatchError;
use crate::mempool::SharedMempool;
use crate::store::StoreClient;
use crate::{COMPONENT, TelemetryInjectorExt};

// BATCH BUILDER
// ================================================================================================

/// Builds [`ProvenBatch`] from sets of transactions.
///
/// Transaction sets are pulled from the mempool at a configurable interval, and passed to
/// a pool of provers for proof generation. Proving is currently unimplemented and is instead
/// simulated via the given proof time and failure rate.
pub struct BatchBuilder {
    /// Represents all batch building workers.
    ///
    /// This pool is always at maximum capacity. Idle workers will be in a [`std::future::Ready`]
    /// state and are immediately available for a new batch building job.
    ///
    /// See also: [`BatchBuilder::wait_for_available_worker`].
    worker_pool: JoinSet<()>,
    batch_interval: Duration,
    /// The batch prover to use.
    ///
    /// If not provided, a local batch prover is used.
    batch_prover: BatchProver,
    /// Simulated block failure rate as a percentage.
    ///
    /// Note: this _must_ be sign positive and less than 1.0.
    failure_rate: f64,
    store: StoreClient,
}

impl BatchBuilder {
    /// Creates a new [`BatchBuilder`] with the given batch prover URL and maximum concurrent batch
    /// building workers.
    ///
    /// If no batch prover URL is provided, a local batch prover is used instead.
    pub fn new(
        store: StoreClient,
        num_workers: NonZeroUsize,
        batch_prover_url: Option<Url>,
        batch_interval: Duration,
    ) -> Self {
        let batch_prover = batch_prover_url
            .map_or(BatchProver::local(MIN_PROOF_SECURITY_LEVEL), BatchProver::remote);

        // It is important that the worker pool is filled to capacity with ready workers. See
        // `Self::worker_pool` and `Self::wait_for_available_worker` for more context.
        let worker_pool = std::iter::repeat_n(std::future::ready(()), num_workers.get()).collect();

        Self {
            batch_interval,
            worker_pool,
            failure_rate: 0.0,
            batch_prover,
            store,
        }
    }

    /// Starts the [`BatchBuilder`], creating and proving batches at the configured interval.
    ///
    /// A pool of batch-proving workers is spawned, which are fed new batch jobs periodically.
    /// A batch is skipped if there are no available workers, or if there are no transactions
    /// available to batch.
    pub async fn run(mut self, mempool: SharedMempool) {
        assert!(
            self.failure_rate < 1.0 && self.failure_rate.is_sign_positive(),
            "Failure rate must be a percentage"
        );

        let mut interval = tokio::time::interval(self.batch_interval);
        // We set the interval's missed tick behaviour to burst. This means we'll catch up missed
        // batches as fast as possible. In other words, we try our best to keep the desired batch
        // interval on average. The other options would result in at least one skipped batch.
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Burst);

        loop {
            interval.tick().await;
            self.build_batch(mempool.clone()).await;
        }
    }

    #[instrument(parent = None, target = COMPONENT, name = "batch_builder.build_batch", skip_all)]
    async fn build_batch(&mut self, mempool: SharedMempool) {
        Span::current().set_attribute("workers.count", self.worker_pool.len());

        self.wait_for_available_worker().await;

        let job = BatchJob {
            failure_rate: self.failure_rate,
            store: self.store.clone(),
            mempool,
            batch_prover: self.batch_prover.clone(),
        };

        self.worker_pool
            .spawn(async move { job.build_batch().await }.instrument(tracing::Span::current()));
    }

    /// Waits for a new batch building worker to become available.
    ///
    /// The worker pool is _always_ at full capacity because:
    ///   - It is instantiated with a full cohort of [`std::future::ready()`].
    ///   - This function removes a worker but it's _always_ added afterwards again in
    ///     `build_batch`, keeping the pool at capacity.
    ///
    /// An alternate implementation might instead check the currently active jobs, but this would
    /// require the same logic as here to handle the case when the pool is at capacity. This
    /// design was chosen instead as it removes this branching logic by "always" having the pool
    /// at max capacity. Instead completed workers wait to be culled by this function.
    #[instrument(target = COMPONENT, name = "batch_builder.wait_for_available_worker", skip_all)]
    async fn wait_for_available_worker(&mut self) {
        // We must crash here because otherwise we have a batch that has been selected from the
        // mempool, but which is now in limbo. This effectively corrupts the mempool.
        if let Err(crash) = self.worker_pool.join_next().await.expect("worker pool is never empty")
        {
            tracing::error!(message=%crash, "Batch worker pool panic'd");
            panic!("Batch worker pool panic: {crash}");
        }
    }
}

// BATCH JOB
// ================================================================================================

/// Represents a single batch building job.
///
/// It is entirely self-contained and performs the full batch creation flow, from selecting the
/// batch from the [`Mempool`] up to and including submitting the results back to the [`Mempool`].
///
/// Errors are also handled internally and are not propagated up.
struct BatchJob {
    /// Simulated block failure rate as a percentage.
    ///
    /// Note: this _must_ be sign positive and less than 1.0.
    failure_rate: f64,
    store: StoreClient,
    batch_prover: BatchProver,
    mempool: SharedMempool,
}

impl BatchJob {
    async fn build_batch(&self) {
        let Some(batch) = self.select_batch().instrument(Span::current()).await else {
            tracing::info!("No transactions available.");
            return;
        };

        batch.inject_telemetry();
        let batch_id = batch.id();

        self.get_batch_inputs(batch)
            .and_then(|(txs, inputs)| Self::propose_batch(txs, inputs) )
            .inspect_ok(TelemetryInjectorExt::inject_telemetry)
            .and_then(|proposed| self.prove_batch(proposed))

            // Failure must be injected before the final pipeline stage i.e. before commit is called. The system cannot
            // handle errors after it considers the process complete (which makes sense).
            .and_then(|x| self.inject_failure(x))
            .and_then(|proven_batch| async { self.commit_batch(proven_batch).await; Ok(()) })
            // Handle errors by propagating the error to the root span and rolling back the batch.
            .inspect_err(|err| Span::current().set_error(err))
            .or_else(|_err| self.rollback_batch(batch_id).never_error())
            // Error has been handled, this is just type manipulation to remove the result wrapper.
            .unwrap_or_else(|_: Never| ())
            .instrument(Span::current())
            .await;
    }

    #[instrument(target = COMPONENT, name = "batch_builder.select_batch", skip_all)]
    async fn select_batch(&self) -> Option<SelectedBatch> {
        self.mempool.lock().await.select_batch()
    }

    #[instrument(target = COMPONENT, name = "batch_builder.get_batch_inputs", skip_all, err)]
    async fn get_batch_inputs(
        &self,
        batch: SelectedBatch,
    ) -> Result<(SelectedBatch, BatchInputs), BuildBatchError> {
        let block_references = batch
            .txs()
            .iter()
            .map(Deref::deref)
            .map(AuthenticatedTransaction::reference_block);
        let unauthenticated_notes = batch
            .txs()
            .iter()
            .map(Deref::deref)
            .flat_map(AuthenticatedTransaction::unauthenticated_note_commitments);

        self.store
            .get_batch_inputs(block_references, unauthenticated_notes)
            .await
            .map_err(BuildBatchError::FetchBatchInputsFailed)
            .map(|inputs| (batch, inputs))
    }

    #[instrument(target = COMPONENT, name = "batch_builder.propose_batch", skip_all, err)]
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
        )
        .map_err(BuildBatchError::ProposeBatchError)
    }

    #[instrument(target = COMPONENT, name = "batch_builder.prove_batch", skip_all, err)]
    async fn prove_batch(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<Arc<ProvenBatch>, BuildBatchError> {
        Span::current().set_attribute("prover.kind", self.batch_prover.kind());

        let proven_batch = match &self.batch_prover {
            BatchProver::Remote(prover) => prover
                .prove(proposed_batch)
                .await
                .map_err(BuildBatchError::RemoteProverClientError),
            BatchProver::Local(prover) => tokio::task::spawn_blocking({
                let prover = prover.clone();
                move || prover.prove(proposed_batch).map_err(BuildBatchError::ProveBatchError)
            })
            .await
            .map_err(BuildBatchError::JoinError)?,
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

    #[instrument(target = COMPONENT, name = "batch_builder.inject_failure", skip_all, err)]
    async fn inject_failure<T>(&self, value: T) -> Result<T, BuildBatchError> {
        let roll = rand::rng().random::<f64>();

        Span::current().set_attribute("failure_rate", self.failure_rate);
        Span::current().set_attribute("dice_roll", roll);

        if roll < self.failure_rate {
            Err(BuildBatchError::InjectedFailure)
        } else {
            Ok(value)
        }
    }

    #[instrument(target = COMPONENT, name = "batch_builder.commit_batch", skip_all)]
    async fn commit_batch(&self, batch: Arc<ProvenBatch>) {
        self.mempool.lock().await.commit_batch(batch);
    }

    #[instrument(target = COMPONENT, name = "batch_builder.rollback_batch", skip_all)]
    async fn rollback_batch(&self, batch_id: BatchId) {
        self.mempool.lock().await.rollback_batch(batch_id);
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

    fn local(security_level: u32) -> Self {
        Self::Local(LocalBatchProver::new(security_level))
    }

    fn remote(endpoint: impl Into<String>) -> Self {
        Self::Remote(RemoteBatchProver::new(endpoint))
    }
}

// TELEMETRY
// ================================================================================================

impl TelemetryInjectorExt for SelectedBatch {
    fn inject_telemetry(&self) {
        Span::current().set_attribute("batch.id", self.id());
        Span::current().set_attribute("transactions.count", self.txs().len());
        // Accumulate all telemetry based on transactions.
        let (tx_ids, input_notes_count, output_notes_count, unauth_notes_count) =
            self.txs().iter().fold(
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
                    unauth_notes_count += tx.unauthenticated_note_commitments().count();
                    (tx_ids, input_notes_count, output_notes_count, unauth_notes_count)
                },
            );
        Span::current().set_attribute("transactions.ids", tx_ids);
        Span::current().set_attribute("transactions.input_notes.count", input_notes_count);
        Span::current().set_attribute("transactions.output_notes.count", output_notes_count);
        Span::current()
            .set_attribute("transactions.unauthenticated_notes.count", unauth_notes_count);
    }
}

impl TelemetryInjectorExt for ProposedBatch {
    fn inject_telemetry(&self) {
        Span::current().set_attribute("batch.expiration_height", self.batch_expiration_block_num());
        Span::current().set_attribute("batch.account_updates.count", self.account_updates().len());
        Span::current().set_attribute("batch.input_notes.count", self.input_notes().num_notes());
        Span::current().set_attribute("batch.output_notes.count", self.output_notes().len());
    }
}
