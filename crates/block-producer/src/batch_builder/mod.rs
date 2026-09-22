use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use futures::TryFutureExt;
use miden_node_proto::domain::sequencer::AuthenticatedTransaction;
use miden_node_store::state::State;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{
    ErrorSpanExt,
    Instrument,
    Span,
    error,
    miden_instrument,
    miden_span_record,
};
use miden_node_utils::shutdown::CancellationToken;
use miden_objects::account_file::AccountFile;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchId, ProposedBatch, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};

use crate::domain::batch::{SelectedBatch, SelectedBatchId};
use crate::errors::{BuildBatchError, StoreError};
use crate::fee_collector::FeeCollectorTransactionBuilder;
use crate::mempool::SharedMempool;
use crate::validator::BlockProducerValidatorClient;
use crate::{COMPONENT, LOG_TARGET};

mod prover;
pub(crate) use prover::BatchProver;

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
    batch_prover: BatchProver,
    fee_collector: FeeCollectorTransactionBuilder,
    validator: BlockProducerValidatorClient,
    state: Arc<State>,
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
    /// Creates a new [`BatchBuilder`] with the given maximum number of concurrent workers.
    pub async fn new(
        state: Arc<State>,
        num_workers: NonZeroUsize,
        intervals: BatchIntervals,
        builder_account_id: AccountId,
        fee_collector_account: AccountFile,
        validator: BlockProducerValidatorClient,
    ) -> anyhow::Result<Self> {
        let fee_collector = FeeCollectorTransactionBuilder::new(
            builder_account_id,
            fee_collector_account,
            &state.view(),
        )
        .await?;

        Ok(Self {
            active_jobs: JoinSet::new(),
            num_workers,
            intervals,
            batch_prover: BatchProver::new(),
            fee_collector,
            validator,
            state,
        })
    }

    /// Starts the [`BatchBuilder`], creating and proving batches dynamically.
    ///
    /// Full batches are spawned on each check and job completion. A batch of any size is attempted
    /// when no batch has been spawned for the maximum batch interval.
    pub async fn run(
        mut self,
        mempool: SharedMempool,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut last_spawn = Instant::now();
        let mut full_batch_check = tokio::time::interval(self.intervals.full_batch_check_interval);
        full_batch_check.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            // Force a batch attempt after the maximum interval, even if it is partial.
            let force_at = tokio::time::sleep_until(last_spawn + self.intervals.max_batch_interval);
            let has_available_worker = self.has_available_worker();
            let has_active_job = !self.active_jobs.is_empty();

            tokio::select! {
                () = shutdown.cancelled() => {
                    Self::abort_active_jobs(&mut self.active_jobs);
                    return Ok(());
                },
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
    )]
    fn build_batch(&mut self, mempool: SharedMempool, batch: SelectedBatch) {
        miden_span_record!(
            workers.active = self.active_jobs.len(),
            workers.capacity = self.num_workers.get()
        );

        let telemetry = batch.telemetry();
        miden_span_record!(
            batch.id = telemetry.batch_id,
            transaction.count = telemetry.transactions_count,
            transaction.ids = telemetry.transaction_ids,
            transaction.input_note.count = telemetry.input_notes_count,
            transaction.output_note.count = telemetry.output_notes_count,
            transaction.unauthenticated_note.count = telemetry.unauthenticated_notes_count
        );
        let job = BatchJob {
            state: self.state.clone(),
            mempool,
            batch_prover: self.batch_prover.clone(),
            fee_collector: self.fee_collector.clone(),
            validator: self.validator.clone(),
        };

        self.active_jobs.spawn(
            async move { Box::pin(job.build_batch(batch)).await }
                .instrument(miden_node_tracing::Span::current()),
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
    )]
    fn select_full_batch(
        mempool: &SharedMempool,
    ) -> Result<Option<SelectedBatch>, BuildBatchError> {
        Ok(mempool.lock().map_err(BuildBatchError::MempoolPoisoned)?.select_full_batch())
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.select_any_batch",
    )]
    fn select_any_batch(mempool: &SharedMempool) -> Result<Option<SelectedBatch>, BuildBatchError> {
        Ok(mempool.lock().map_err(BuildBatchError::MempoolPoisoned)?.select_any_batch())
    }

    fn has_available_worker(&self) -> bool {
        self.active_jobs.len() < self.num_workers.get()
    }

    fn abort_active_jobs(active_jobs: &mut JoinSet<Result<(), BuildBatchError>>) {
        active_jobs.abort_all();
    }

    fn handle_job_result(
        result: Result<Result<(), BuildBatchError>, JoinError>,
    ) -> Result<(), BuildBatchError> {
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err),
            Err(crash) => {
                error!(
                    &crash,
                    target: LOG_TARGET,
                    "Batch worker pool panic'd"
                );
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
    state: Arc<State>,
    batch_prover: BatchProver,
    fee_collector: FeeCollectorTransactionBuilder,
    validator: BlockProducerValidatorClient,
    mempool: SharedMempool,
}

impl BatchJob {
    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.build_batch_job",
        err,
    )]
    async fn build_batch(&self, batch: SelectedBatch) -> Result<(), BuildBatchError> {
        let batch_id = batch.id();

        let result = Box::pin(self.get_batch_inputs(batch))
            .inspect_ok(|proposed| {
                let telemetry = proposed_batch_telemetry(proposed);
                miden_span_record!(
                    batch.expiration_height = telemetry.expiration_height,
                    batch.account_update.count = telemetry.account_updates_count,
                    batch.input_note.count = telemetry.input_notes_count,
                    batch.output_note.count = telemetry.output_notes_count
                );
            })
            .and_then(|proposed| self.batch_prover.prove(proposed))
            .and_then(|proven_batch| async { self.commit_batch(Arc::new(proven_batch)) })
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
        err,
    )]
    async fn get_batch_inputs(
        &self,
        selected: SelectedBatch,
    ) -> Result<ProposedBatch, BuildBatchError> {
        let fee_notes = selected.collectible_fee_notes().to_vec();
        let mut block_numbers: BTreeSet<_> = selected
            .transactions()
            .iter()
            .map(Deref::deref)
            .map(AuthenticatedTransaction::reference_block)
            .map(|(block_num, _)| block_num)
            .collect();
        let reference_block = selected.parameters().reference_block;
        let note_ids = selected
            .transactions()
            .iter()
            .map(Deref::deref)
            .flat_map(AuthenticatedTransaction::unauthenticated_note_ids)
            .collect();

        let view = self.state.view();
        let note_inclusion_proofs = view
            .get_note_inclusion_proofs(reference_block, note_ids)
            .await
            .map_err(StoreError::GetNoteInclusionProofsFailed)
            .map_err(BuildBatchError::FetchBatchInputsFailed)?;
        block_numbers
            .extend(note_inclusion_proofs.values().map(|proof| proof.location().block_num()));
        let partial_blockchain = view
            .get_block_inclusion_proofs(reference_block, block_numbers)
            .await
            .map_err(StoreError::GetBlockInclusionProofsFailed)
            .map_err(BuildBatchError::FetchBatchInputsFailed)?;
        let reference_block_header = view
            .get_block_header(Some(reference_block), false)
            .await
            .map_err(StoreError::GetBlockHeaderFailed)
            .map_err(BuildBatchError::FetchBatchInputsFailed)?
            .0
            .expect("reference block header should exist");

        let mut transactions: Vec<_> = selected
            .into_transactions()
            .into_iter()
            .map(|tx| tx.proven_transaction())
            .collect();

        // A deployed collector must consume at least one note to prevent replay.
        if !fee_notes.is_empty() {
            let protocol_config = view
                .get_protocol_config(reference_block_header.protocol_config_commitment())
                .await
                .map_err(StoreError::GetProtocolConfigFailed)
                .map_err(BuildBatchError::FetchBatchInputsFailed)?
                .expect("the reference block's protocol configuration should exist");
            let genesis = view
                .get_block_header(Some(BlockNumber::GENESIS), false)
                .await
                .map_err(StoreError::GetBlockHeaderFailed)
                .map_err(BuildBatchError::FetchBatchInputsFailed)?
                .0
                .expect("the genesis block header should exist")
                .commitment();

            let fee_collector = self.fee_collector.clone();
            let executed_fee_collection_tx = fee_collector
                .execute(
                    fee_notes,
                    reference_block_header.clone(),
                    protocol_config,
                    partial_blockchain.clone(),
                    &view,
                )
                .await
                .map_err(BuildBatchError::BuildBatchFeeTransaction)?;
            let inputs = executed_fee_collection_tx.tx_inputs().clone();
            let fee_collection_tx = spawn_blocking_in_current_span(move || {
                FeeCollectorTransactionBuilder::prove(executed_fee_collection_tx)
            })
            .await
            .map_err(BuildBatchError::JoinError)?
            .map_err(BuildBatchError::BuildBatchFeeTransaction)?;
            self.validator
                .validate_transaction(
                    &fee_collection_tx,
                    &inputs,
                    genesis,
                    reference_block_header.validator_config(),
                )
                .await
                .map_err(BuildBatchError::ValidateBatchFeeTransaction)?;
            transactions.push(Arc::new(fee_collection_tx));
        }

        ProposedBatch::new(
            transactions,
            reference_block_header,
            partial_blockchain,
            note_inclusion_proofs,
            MIN_PROOF_SECURITY_LEVEL,
        )
        .map_err(BuildBatchError::ProposeBatchError)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "batch_builder.commit_batch",
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
    )]
    fn rollback_batch(&self, batch_id: SelectedBatchId) -> Result<(), BuildBatchError> {
        self.mempool
            .lock()
            .map_err(BuildBatchError::MempoolPoisoned)?
            .rollback_batch(batch_id);
        Ok(())
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
            batch_id: self.id().as_batch_id(),
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

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::time::Duration;

    use miden_node_utils::genesis::GenesisBlock;
    use miden_protocol::ONE;
    use miden_protocol::block::{BlockSignatures, SignedBlock};
    use miden_testing::{Auth, MockChain};
    use miden_tx::LocalTransactionProver;

    use super::*;
    use crate::mempool::{Mempool, MempoolConfig};
    use crate::store::get_tx_inputs;
    use crate::test_utils::{mock_collection_account, mock_native_faucet};

    #[tokio::test(flavor = "multi_thread")]
    async fn builds_batches_without_fee_notes() -> anyhow::Result<()> {
        let (mut account, auth_secret_keys) = mock_collection_account().into_parts();
        account.set_nonce(ONE)?;
        let collector = AccountFile::new(account, auth_secret_keys);
        let faucet = mock_native_faucet();
        let mut chain = MockChain::builder().verification_base_fee(0).fee_faucet_id(faucet.id());
        chain.add_account(faucet)?;
        chain.add_account(collector.account().clone())?;
        let wallet = chain.add_existing_wallet(Auth::basic_ecdsa())?;
        let chain = chain.build()?;
        let executed = chain.build_transaction(wallet.id()).build()?.execute().await?;
        let transaction = LocalTransactionProver::default().prove(executed)?;
        assert_eq!(transaction.output_notes().num_notes(), 0);

        let directory = tempfile::tempdir()?;
        let genesis = chain.latest_block();
        let genesis = GenesisBlock::new(
            SignedBlock::new(
                genesis.header().clone(),
                genesis.body().clone(),
                BlockSignatures::new(Vec::new())?,
            )?,
            chain.protocol_config().clone(),
        )?;
        State::bootstrap(genesis, directory.path())?;
        let (state, ..) = State::for_tests(directory.path()).await;
        let inputs = get_tx_inputs(&state, &transaction).await?;
        let transaction =
            Arc::new(AuthenticatedTransaction::new_unchecked(Arc::new(transaction), inputs)?);
        let mempool = Mempool::shared(BlockNumber::GENESIS, MempoolConfig::default());
        mempool.lock().unwrap().add_transaction(transaction)?;
        let selected = mempool.lock().unwrap().select_any_batch().unwrap();
        let selected_id = selected.id().as_batch_id();
        let fee_collector =
            FeeCollectorTransactionBuilder::new(wallet.id(), collector, &state.view()).await?;
        let job = BatchJob {
            state,
            batch_prover: BatchProver::new(),
            fee_collector,
            validator: BlockProducerValidatorClient::new(Vec::new(), Duration::from_secs(1))?,
            mempool,
        };

        let proposed = Box::pin(job.get_batch_inputs(selected)).await?;
        assert_eq!(proposed.id(), selected_id);
        assert_eq!(proposed.transactions().len(), 1);
        assert!(proposed.output_notes().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn abort_active_jobs_cancels_batch_jobs_without_waiting_for_completion() {
        let mut active_jobs = JoinSet::new();
        active_jobs.spawn(async { pending::<Result<(), BuildBatchError>>().await });

        BatchBuilder::abort_active_jobs(&mut active_jobs);

        let result = tokio::time::timeout(Duration::from_millis(100), active_jobs.join_next())
            .await
            .expect("aborted batch job should be joinable immediately")
            .expect("join set should contain the aborted batch job");

        assert!(result.is_err_and(|err| err.is_cancelled()));
    }
}
