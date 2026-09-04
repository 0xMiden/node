use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use backon::ExponentialBuilder;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{
    ErrorSpanExt,
    Instrument,
    info,
    miden_instrument,
    miden_span_record,
    warn,
};
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::retry::{self, Retryable};
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountPatch,
    AccountStorageHeader,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{AssetId, AssetWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::errors::{
    AccountError,
    AssetError,
    ProtocolConfigError,
    TransactionInputError,
};
use miden_protocol::note::{Note, NoteId, NoteScript, NoteScriptRoot};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNote,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
    TransactionId,
    TransactionInputs,
};
use miden_protocol::vm::FutureMaybeSend;
use miden_standards::account::fees::FeePolicyManager;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{
    DataStore,
    DataStoreError,
    ExecutionOptions,
    FailedNote,
    LoadedMastForest,
    MastForestStore,
    NoteCheckerError,
    NoteConsumptionChecker,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionMastStore,
    TransactionProverError,
};

use crate::actor::candidate::{SponsoredFeatureNote, TransactionCandidate};
use crate::clients::{RemoteTransactionProver, RpcClient, RpcError};
use crate::db::NtxDbReader;
use crate::{COMPONENT, LOG_TARGET};

#[derive(Debug, thiserror::Error)]
pub enum NtxError {
    #[error("note inputs were invalid")]
    InputNotes(#[source] TransactionInputError),
    #[error("failed to filter notes")]
    NoteFilter(#[source] NoteCheckerError),
    #[error("all notes failed to be executed")]
    AllNotesFailed(Vec<FailedNote>),
    #[error("failed to execute transaction")]
    Execution(#[source] TransactionExecutorError),
    #[error("failed to prove transaction")]
    Proving(#[source] TransactionProverError),
    #[error("failed to submit transaction")]
    Submission(#[source] tonic::Status),
    #[error("failed to read the fee asset ID from the network account")]
    FeeAssetStorage(#[source] AccountError),
    #[error("invalid fee asset ID in the network account")]
    FeeAsset(#[source] AssetError),
    #[error("invalid protocol configuration for the network account")]
    ProtocolConfig(#[source] ProtocolConfigError),
    #[error("network account fee asset does not match the reference block protocol configuration")]
    ProtocolConfigCommitmentMismatch,
}

type NtxResult<T> = Result<T, NtxError>;

/// Returns `true` for gRPC status codes that indicate a transient transport- or server-side problem
/// worth retrying. Content-rejection codes (`InvalidArgument`, `FailedPrecondition`, ...) reflect
/// the batch itself and are not retried.
fn is_transient_status(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Cancelled
            | tonic::Code::Aborted
            | tonic::Code::Unknown
            | tonic::Code::Internal
            | tonic::Code::ResourceExhausted,
    )
}

/// Returns `true` for `RpcError`s that originate from a transient gRPC condition. All other RPC
/// errors (deserialization, missing fields) are content errors and are not retried.
fn is_transient_rpc_error(err: &RpcError) -> bool {
    matches!(err, RpcError::GrpcClientError(status) if is_transient_status(status))
}

/// Maximum number of retries applied to a single transient request before the error is propagated
/// to the actor-level retry.
const MAX_REQUEST_RETRIES: usize = 20;

/// Builds the [`ExponentialBuilder`] used to back off retries on transient request failures.
fn request_backoff(initial: Duration, max: Duration) -> ExponentialBuilder {
    retry::exponential_bounded(initial, max, MAX_REQUEST_RETRIES)
}

/// Emits a structured warning for a transient NTX request failure that is about to be retried.
fn log_transient_retry<E: std::error::Error>(operation: &'static str, err: &E, sleep: Duration) {
    warn!(
        err,
        target: COMPONENT,
        "ntx transient request failure; retrying after backoff",
        operation.name = operation,
        retry.delay_ms = sleep.as_millis() as u64
    );
}

/// The result of a successful transaction execution.
pub struct NtxExecutionResult {
    /// ID of the submitted transaction.
    pub tx_id: TransactionId,
    /// The account patch the transaction produced, applied to the actor's in-memory account once
    /// the transaction lands.
    pub account_patch: AccountPatch,
    /// Notes that failed consumability filtering for a genuine reason (not a cycle-budget drop).
    /// Their attempt counters should be incremented.
    pub failed_notes: Vec<FailedNote>,
    /// Notes dropped by the checker only because the combined per-tx cycle budget was exhausted,
    /// yet proven consumable on their own. They are intentionally left un-penalized so
    /// `available_notes` re-selects them next round, letting a large note land in its own
    /// transaction once its batch-mates have committed.
    pub deferred_notes: Vec<FailedNote>,
    /// Notes whose own consumption exceeds the per-tx cycle budget. They can never be consumed in
    /// any transaction and should be discarded immediately.
    pub oversized_notes: Vec<FailedNote>,
    /// Note scripts fetched from the remote RPC service that should be persisted to the local DB
    /// cache.
    pub fetched_scripts: Vec<(Word, NoteScript)>,
}

/// The outcome of consumability filtering: the executable set plus the failed notes partitioned by
/// how the actor should treat them. See [`NtxExecutionResult`] for the meaning of each bucket.
struct FilteredNotes {
    successful: InputNotes<InputNote>,
    failed: Vec<FailedNote>,
    deferred: Vec<FailedNote>,
    oversized: Vec<FailedNote>,
}

// NETWORK TRANSACTION CONTEXT
// ================================================================================================

/// Provides the context for execution [network transaction candidates](TransactionCandidate).
#[derive(Clone)]
pub struct NtxContext {
    /// The prover to delegate proofs to.
    prover: RemoteTransactionProver,

    /// The RPC client for retrieving note scripts.
    rpc: RpcClient,

    /// LRU cache for storing retrieved note scripts to avoid repeated RPC calls.
    script_cache: LruCache<Word, NoteScript>,

    /// Local database for persistent note script caching.
    db: NtxDbReader,

    /// Maximum number of VM execution cycles for network transactions.
    max_cycles: u32,

    /// [`TransactionArgs`] shared by every network transaction. Cloned into each executed
    /// transaction. Currently carries the canonical expiration script and its delta word.
    tx_args: TransactionArgs,

    /// [`ExponentialBuilder`] used to back off retries on transient request failures.
    request_backoff: ExponentialBuilder,
}

impl NtxContext {
    /// Creates a new [`NtxContext`] instance.
    #[expect(
        clippy::too_many_arguments,
        reason = "execution context aggregates actor resources"
    )]
    pub fn new(
        prover: RemoteTransactionProver,
        rpc: RpcClient,
        script_cache: LruCache<Word, NoteScript>,
        db: NtxDbReader,
        max_cycles: u32,
        tx_args: TransactionArgs,
        request_backoff_initial: Duration,
        request_backoff_max: Duration,
    ) -> Self {
        let request_backoff = request_backoff(request_backoff_initial, request_backoff_max);
        Self {
            prover,
            rpc,
            script_cache,
            db,
            max_cycles,
            tx_args,
            request_backoff,
        }
    }

    /// Returns the [`ExponentialBuilder`] used for per-request retry backoff.
    fn request_backoff(&self) -> ExponentialBuilder {
        self.request_backoff
    }

    /// Creates a [`TransactionExecutor`] configured with the network transaction cycle limit.
    fn create_executor<'a, 'b>(
        &self,
        data_store: &'a NtxDataStore,
    ) -> TransactionExecutor<'a, 'b, NtxDataStore, UnreachableAuth> {
        let exec_options = ExecutionOptions::new(
            Some(self.max_cycles),
            self.max_cycles,
            ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
        )
        .expect("max_cycles should be within valid range");

        TransactionExecutor::new(data_store)
            .with_options(exec_options)
            .expect("execution options should be valid for transaction executor")
    }

    /// Executes a transaction end-to-end: filtering, executing, proving, and submitting through
    /// the RPC service.
    ///
    /// The provided [`TransactionCandidate`] is processed in the following stages:
    /// 1. Note filtering – all input notes are checked for consumability. Any notes that cannot be
    ///    executed are returned as [`FailedNote`]s.
    /// 2. Execution – the remaining notes are executed against the account state.
    /// 3. Proving – a proof is generated for the executed transaction.
    /// 4. Submission – the proven transaction is submitted through the RPC service.
    ///
    /// # Returns
    ///
    /// On success, returns an [`NtxExecutionResult`] containing the transaction ID, the account
    /// delta the transaction produced, any notes that failed during filtering, and note scripts
    /// fetched from the remote RPC service that should be persisted to the local DB cache.
    ///
    /// # Errors
    ///
    /// Returns an [`NtxError`] if any step of the pipeline fails, including:
    /// - Note filtering (e.g., all notes fail consumability checks).
    /// - Transaction execution.
    /// - Proof generation.
    /// - Submission to the network.
    #[miden_instrument(
        target = COMPONENT,
        name = "ntx.execute_transaction",
        err,
    )]
    pub fn execute_transaction(
        self,
        tx: TransactionCandidate,
    ) -> impl FutureMaybeSend<NtxResult<NtxExecutionResult>> {
        let num_notes = tx.num_notes();
        let TransactionCandidate {
            account,
            notes,
            chain_tip_header,
            chain_mmr,
        } = tx;
        miden_span_record!(
            account.id = account.id(),
            account.id.network_prefix = account.id().prefix(),
            note.count = num_notes,
            reference_block.number = chain_tip_header.block_num()
        );

        async move {
            Box::pin(async move {
                // VM execution (note filtering + transaction execution) is CPU-intensive and may
                // not yield between await points. Run it on a dedicated blocking thread while using
                // the parent runtime handle to drive async RPC callbacks.
                let ctx = self.clone();
                let handle = tokio::runtime::Handle::current();
                let span = miden_node_tracing::Span::current();

                let (executed_tx, failed_notes, deferred_notes, oversized_notes, scripts_to_cache) =
                    spawn_blocking_in_current_span(move || {
                        let data_store = NtxDataStore::new(
                            account,
                            chain_tip_header,
                            chain_mmr,
                            ctx.rpc.clone(),
                            ctx.script_cache.clone(),
                            ctx.db.clone(),
                            ctx.request_backoff,
                        )?;
                        handle.block_on(
                            async {
                                let FilteredNotes { successful, failed, deferred, oversized } =
                                    ctx.filter_notes(&data_store, notes).await?;
                                let executed_tx =
                                    Box::pin(ctx.execute(&data_store, successful)).await?;
                                let scripts_to_cache = data_store.take_fetched_scripts();
                                Ok::<_, NtxError>((
                                    executed_tx,
                                    failed,
                                    deferred,
                                    oversized,
                                    scripts_to_cache,
                                ))
                            }
                            .instrument(span),
                        )
                    })
                    .await
                    .unwrap_or_else(|err| std::panic::resume_unwind(err.into_panic()))?;

                // Destructure the executed tx into its parts; the actor applies the account patch
                // to its in-memory account once this transaction lands in a committed block.
                let (tx_inputs, _, account_patch, _) = executed_tx.into_parts();

                // Prove transaction.
                let proven_tx = Box::pin(self.prove(&tx_inputs)).await?;

                // Submit transaction through the RPC service.
                self.submit(&proven_tx, &tx_inputs).await?;

                Ok(NtxExecutionResult {
                    tx_id: proven_tx.id(),
                    account_patch,
                    failed_notes,
                    deferred_notes,
                    oversized_notes,
                    fetched_scripts: scripts_to_cache,
                })
            })
            .in_current_span()
            .await
            .inspect_err(|err| miden_node_tracing::Span::current().set_error(err))
        }
    }

    /// Filters the candidate's bundles down to those that can execute together, and classifies
    /// the rest.
    ///
    /// [`NoteConsumptionChecker`] eliminates one note at a time. Fee collection runs in the
    /// account's auth procedure, so an uncovered fee fails in the epilogue and drops the checker
    /// into that search, where a feature note and its sponsorship are each invalid alone. Valid
    /// pairs are discarded along with the note that actually failed.
    ///
    /// So the batch is checked once, then every bundle the checker did not prove is re-offered on
    /// top of what it did, trying the most sponsorships first. A trial is kept only if the checker
    /// proves that exact set, so the result never regresses. For `[F0, S0, F1]` - a feature note,
    /// its sponsorship, and an unsponsored feature note - the checker fails all three; the retry
    /// proves `[F0, S0]` and records only `F1`.
    ///
    /// TODO: drop this once the checker can test a bundle atomically, see
    /// <https://github.com/0xMiden/protocol/issues/3710>.
    ///
    /// # Guarantees
    ///
    /// - On success, the returned [`InputNotes`] set is guaranteed to be non-empty.
    /// - The original ordering of notes is not preserved if any notes have failed.
    ///
    /// # Errors
    ///
    /// Returns an [`NtxError`] if:
    /// - The consumability check fails unexpectedly.
    /// - All notes fail the check (i.e., no note is consumable).
    #[miden_instrument(
        target = COMPONENT,
        name = "ntx.execute_transaction.filter_notes",
        err,
    )]
    async fn filter_notes(
        &self,
        data_store: &NtxDataStore,
        sponsored_notes: Vec<SponsoredFeatureNote>,
    ) -> NtxResult<FilteredNotes> {
        let all_notes = sponsored_notes.iter().flat_map(bundled_notes).collect::<Vec<_>>();
        let (mut successful_notes, batch_failed) =
            self.check_consumability(data_store, all_notes).await?;

        // An epilogue failure sends the note checker through a greedy search that adds one note at
        // a time. It cannot rediscover a feature and sponsorship that only execute together. Keep
        // the checker's proven-successful set as a monotonic baseline and re-offer each missing
        // dependency-closed variant on top of it. A failed retry never replaces that baseline.
        successful_notes = retry_sponsored_notes(
            &sponsored_notes,
            successful_notes,
            |trial: Vec<Note>| async move {
                let trial_len = trial.len();
                let (trial_successful, trial_failed) =
                    self.check_consumability(data_store, trial).await?;

                // The checker first executes the exact trial. No failures and a matching
                // cardinality therefore prove that complete set; otherwise its fallback result is
                // not allowed to replace the previously proven baseline.
                Ok((trial_failed.is_empty() && trial_successful.len() == trial_len)
                    .then_some(trial_successful))
            },
        )
        .await?;
        let successful_ids = successful_notes.iter().map(Note::id).collect::<BTreeSet<_>>();

        let sponsor_to_feature = sponsored_notes
            .iter()
            .flat_map(|sponsored| {
                let feature_id = sponsored.feature.as_note().id();
                sponsored
                    .sponsorships
                    .iter()
                    .map(move |sponsorship| (sponsorship.id(), feature_id))
            })
            .collect::<HashMap<_, _>>();

        // The batch failure list partitions the original input, so removing every note rescued by a
        // retry yields the final failures. If a feature executes without one of its optional
        // sponsorships, suppress that sponsorship's failure too: charging it to the feature would
        // penalize a note which is being submitted successfully.
        let failed = batch_failed
            .into_iter()
            .filter(|failed| {
                should_record_failure(failed.note().id(), &successful_ids, &sponsor_to_feature)
            })
            .collect::<Vec<_>>();

        for failed_note in &failed {
            info!(
                failed_note.error(),
                target: LOG_TARGET,
                "note failed consumability check",
                note.id = failed_note.note().id(),
                note.nullifier = failed_note.note().nullifier()
            );
        }

        let successful = InputNotes::from_unauthenticated_notes(successful_notes)
            .map_err(NtxError::InputNotes)?;

        // If none are successful, abort.
        if successful.is_empty() {
            return Err(NtxError::AllNotesFailed(failed));
        }

        let (cycle_limited, failed) = partition_cycle_limited(failed);
        let (deferred, oversized) = self.classify_cycle_limited(data_store, cycle_limited).await;

        Ok(FilteredNotes { successful, failed, deferred, oversized })
    }

    /// Runs the consumability checker over `notes` and returns the notes it accepted alongside the
    /// notes it rejected.
    async fn check_consumability(
        &self,
        data_store: &NtxDataStore,
        notes: Vec<Note>,
    ) -> NtxResult<(Vec<Note>, Vec<FailedNote>)> {
        let executor = self.create_executor(data_store);
        let checker = NoteConsumptionChecker::new(&executor);

        let consumption_info = Box::pin(checker.check_notes_consumability(
            data_store.account.id(),
            data_store.reference_block.block_num(),
            notes,
            self.tx_args.clone(),
        ))
        .await
        .map_err(NtxError::NoteFilter)?;

        let (successful, failed) = consumption_info.into_parts();
        Ok((successful.into_iter().map(|s| s.note().clone()).collect(), failed))
    }

    /// Splits cycle-limited failed notes into `(deferred, oversized)` by re-checking each one on
    /// its own.
    async fn classify_cycle_limited(
        &self,
        data_store: &NtxDataStore,
        cycle_limited: Vec<FailedNote>,
    ) -> (Vec<FailedNote>, Vec<FailedNote>) {
        let mut deferred = Vec::new();
        let mut oversized = Vec::new();
        for failed in cycle_limited {
            if self.note_exceeds_budget_alone(data_store, failed.note()).await {
                oversized.push(failed);
            } else {
                deferred.push(failed);
            }
        }
        (deferred, oversized)
    }

    /// Returns `true` if the note trips the cycle limit even as a single-note transaction, i.e. its
    /// own consumption exceeds the per-tx cycle budget and it can never be consumed.
    async fn note_exceeds_budget_alone(&self, data_store: &NtxDataStore, note: &Note) -> bool {
        let executor = self.create_executor(data_store);
        let checker = NoteConsumptionChecker::new(&executor);

        match Box::pin(checker.check_notes_consumability(
            data_store.account.id(),
            data_store.reference_block.block_num(),
            vec![note.clone()],
            self.tx_args.clone(),
        ))
        .await
        {
            Ok(info) => {
                let (successful, failed) = info.into_parts();
                // Alone and still cycle-limited: the note needs ~the entire budget for itself.
                successful.is_empty() && failed.iter().any(|f| f.num_cycles().is_some())
            },
            Err(err) => {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "isolation re-check for a cycle-limited note failed; treating it as deferrable",
                    note.id = note.id()
                );
                false
            },
        }
    }

    /// Creates an executes a transaction with the network account and the given set of notes.
    #[miden_instrument(
        target = COMPONENT,
        name = "ntx.execute_transaction.execute",
        err,
    )]
    async fn execute(
        &self,
        data_store: &NtxDataStore,
        notes: InputNotes<InputNote>,
    ) -> NtxResult<ExecutedTransaction> {
        let executor = self.create_executor(data_store);

        // Attach the canonical expiration script (with its delta args) so the submitted tx is
        // rejected on-chain if it does not land within the configured block delta. Serviced network
        // accounts must allowlist this script's root; see the `tx_args` field docs.
        let tx_args = self.tx_args.clone();

        Box::pin(executor.execute_transaction(
            data_store.account.id(),
            data_store.reference_block.block_num(),
            notes,
            tx_args,
        ))
        .await
        .map_err(NtxError::Execution)
    }

    /// Delegates the transaction proof to the configured remote prover.
    ///
    /// Transient transport failures against the remote prover are retried in-place; intrinsic
    /// proving errors (witness rejected, malformed inputs) escape on the first attempt.
    #[miden_instrument(
        target = COMPONENT,
        name = "ntx.execute_transaction.prove",
        err,
    )]
    async fn prove(&self, tx_inputs: &TransactionInputs) -> NtxResult<ProvenTransaction> {
        (|| async { self.prover.prove(tx_inputs).await })
            .retry(self.request_backoff())
            .when(|err| matches!(err, TransactionProverError::Other { .. }))
            .notify(|err, dur| {
                log_transient_retry("remote_prover.prove", err, dur);
            })
            .await
            .map_err(NtxError::Proving)
    }

    /// Submits the transaction through the RPC service.
    ///
    /// Transient gRPC failures (`Unavailable`, `DeadlineExceeded`, ...) are retried in-place;
    /// content-rejection codes escape on the first attempt so the actor can mark the batch failed.
    #[miden_instrument(
        target = COMPONENT,
        name = "ntx.execute_transaction.submit",
        err,
    )]
    async fn submit(
        &self,
        proven_tx: &ProvenTransaction,
        tx_inputs: &TransactionInputs,
    ) -> NtxResult<()> {
        (|| async { self.rpc.submit_proven_tx(proven_tx, tx_inputs).await })
            .retry(self.request_backoff())
            .when(is_transient_status)
            .notify(|status, dur| {
                log_transient_retry("rpc.submit_proven_tx", status, dur);
            })
            .await
            .map_err(NtxError::Submission)
    }
}

/// Returns a bundle's notes: the feature note followed by the sponsorships that pay its fee.
fn bundled_notes(sponsored: &SponsoredFeatureNote) -> Vec<Note> {
    std::iter::once(sponsored.feature.as_note().clone())
        .chain(sponsored.sponsorships.iter().cloned())
        .collect()
}

/// Returns the missing, dependency-closed additions to try for `sponsored` as successively smaller
/// sponsorship prefixes in candidate order.
///
/// This is intentionally linear in the number of sponsorships rather than an exhaustive subset
/// search. It relies on sponsorship ingestion rejecting structurally invalid notes. Notes already
/// in `successful` are never re-offered or removed.
fn retry_variants(
    sponsored: &SponsoredFeatureNote,
    successful: &BTreeSet<NoteId>,
) -> Vec<Vec<Note>> {
    let feature = sponsored.feature.as_note();
    if successful.contains(&feature.id()) {
        return Vec::new();
    }

    let missing_sponsorships = sponsored
        .sponsorships
        .iter()
        .filter(|sponsorship| !successful.contains(&sponsorship.id()))
        .cloned()
        .collect::<Vec<_>>();

    (0..=missing_sponsorships.len())
        .rev()
        .map(|prefix_len| {
            std::iter::once(feature.clone())
                .chain(missing_sponsorships[..prefix_len].iter().cloned())
                .collect()
        })
        .collect()
}

/// Re-offers each unproven bundle on top of `successful_notes`, returning the largest set the
/// checker proved. A failed trial never replaces the baseline.
///
/// `check_exact` runs one trial and returns the proven set, or `None` when the checker did not
/// prove that exact set. It is a parameter so the retry order can be tested without a VM.
async fn retry_sponsored_notes(
    sponsored_notes: &[SponsoredFeatureNote],
    mut successful_notes: Vec<Note>,
    mut check_exact: impl AsyncFnMut(Vec<Note>) -> NtxResult<Option<Vec<Note>>>,
) -> NtxResult<Vec<Note>> {
    let mut successful_ids = successful_notes.iter().map(Note::id).collect::<BTreeSet<_>>();

    for sponsored in sponsored_notes {
        for additions in retry_variants(sponsored, &successful_ids) {
            let mut trial = successful_notes.clone();
            trial.extend(additions);

            if let Some(trial_successful) = check_exact(trial).await? {
                successful_notes = trial_successful;
                successful_ids = successful_notes.iter().map(Note::id).collect::<BTreeSet<_>>();
                break;
            }
        }
    }

    Ok(successful_notes)
}

/// Returns whether a batch-check failure still applies after bundle retries have completed.
fn should_record_failure(
    failed_note: NoteId,
    successful: &BTreeSet<NoteId>,
    sponsor_to_feature: &HashMap<NoteId, NoteId>,
) -> bool {
    !successful.contains(&failed_note)
        && sponsor_to_feature
            .get(&failed_note)
            .is_none_or(|feature| !successful.contains(feature))
}

/// Splits failed notes into `(cycle_limited, genuine)`.
fn partition_cycle_limited(failed: Vec<FailedNote>) -> (Vec<FailedNote>, Vec<FailedNote>) {
    failed.into_iter().partition(|note| note.num_cycles().is_some())
}

// NETWORK TRANSACTION DATA STORE
// ================================================================================================

/// A [`DataStore`] implementation which provides transaction inputs for a single account and
/// reference block with LRU caching for note scripts.
///
/// This implementation includes an LRU (Least Recently Used) cache for note scripts to improve
/// performance by avoiding repeated RPC calls for the same script roots. The cache automatically
/// manages memory usage by evicting least recently used entries when the cache reaches capacity.
///
/// This is sufficient for executing a network transaction.
struct NtxDataStore {
    /// The native account, shared with the actor via `Arc` to avoid a deep clone per transaction.
    account: Arc<Account>,
    reference_block: BlockHeader,
    protocol_config: ProtocolConfig,
    /// The chain MMR, wrapped in `Arc` to avoid expensive clones when reading the chain state.
    chain_mmr: Arc<PartialBlockchain>,
    mast_store: TransactionMastStore,
    /// RPC client for retrieving note scripts.
    rpc: RpcClient,
    /// LRU cache for storing retrieved note scripts to avoid repeated RPC calls.
    script_cache: LruCache<Word, NoteScript>,
    /// Local database for persistent note script.
    db: NtxDbReader,
    /// Scripts fetched from the remote RPC service during execution, to be persisted by the
    /// coordinator.
    fetched_scripts: Arc<Mutex<Vec<(Word, NoteScript)>>>,
    /// Maps storage map roots to storage slot names.
    ///
    /// The RPC service identifies maps by slot name. The [`DataStore`] interface identifies maps by
    /// root. Native and foreign account loading populate this map before witness retrieval.
    ///
    /// The mapping for a loaded account remains stable during transaction execution. A transaction
    /// cannot access a storage slot that it creates during the same execution.
    ///
    /// Two storage maps can have the same root. In this case, the last inserted slot name replaces
    /// the other slot name. Identical maps have identical witnesses, so the selected slot does not
    /// change the witness.
    storage_slots: Arc<Mutex<HashMap<(AccountId, Word), StorageSlotName>>>,
    /// Per-request retry backoff for transient RPC failures.
    request_backoff: ExponentialBuilder,
}

impl NtxDataStore {
    /// Creates a new `NtxDataStore` with default cache size.
    fn new(
        account: Arc<Account>,
        reference_block: BlockHeader,
        chain_mmr: Arc<PartialBlockchain>,
        rpc: RpcClient,
        script_cache: LruCache<Word, NoteScript>,
        db: NtxDbReader,
        request_backoff: ExponentialBuilder,
    ) -> NtxResult<Self> {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(account.code());

        let fee_asset_id = account
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .map_err(NtxError::FeeAssetStorage)?
            .try_into()
            .map_err(NtxError::FeeAsset)?;
        let protocol_config =
            ProtocolConfig::current(fee_asset_id).map_err(NtxError::ProtocolConfig)?;
        if protocol_config.to_commitment() != reference_block.protocol_config_commitment() {
            return Err(NtxError::ProtocolConfigCommitmentMismatch);
        }

        Ok(Self {
            account,
            reference_block,
            protocol_config,
            chain_mmr,
            mast_store,
            rpc,
            script_cache,
            db,
            fetched_scripts: Arc::new(Mutex::new(Vec::new())),
            storage_slots: Arc::new(Mutex::new(HashMap::default())),
            request_backoff,
        })
    }

    /// Returns the [`ExponentialBuilder`] used for per-request retry backoff against the RPC
    /// service.
    fn rpc_backoff(&self) -> ExponentialBuilder {
        self.request_backoff
    }

    /// Returns the list of note scripts fetched from the remote RPC service during execution.
    fn take_fetched_scripts(&self) -> Vec<(Word, NoteScript)> {
        self.fetched_scripts
            .lock()
            .expect("fetched scripts lock poisoned")
            .drain(..)
            .collect()
    }

    /// Registers storage map slot names for the given account ID and storage header.
    ///
    /// These slot names are subsequently used to query for storage map witnesses against the RPC service.
    fn register_storage_map_slots(
        &self,
        account_id: AccountId,
        storage_header: &AccountStorageHeader,
    ) {
        let mut storage_slots = self.storage_slots.lock().expect("storage slots lock poisoned");
        for slot_header in storage_header.slots() {
            if let StorageSlotType::Map = slot_header.slot_type() {
                storage_slots.insert((account_id, slot_header.value()), slot_header.name().clone());
            }
        }
    }
}

impl DataStore for NtxDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        async move {
            if self.account.id() != account_id {
                return Err(DataStoreError::AccountNotFound(account_id));
            }

            // The latest supplied reference block must match the current reference block.
            match ref_blocks.last().copied() {
                Some(reference) if reference == self.reference_block.block_num() => {},
                Some(other) => return Err(DataStoreError::BlockNotFound(other)),
                None => return Err(DataStoreError::other("no reference block requested")),
            }

            // Register slot names from the native account for later use.
            self.register_storage_map_slots(account_id, &self.account.storage().to_header());

            let partial_account = PartialAccount::from(self.account.as_ref());
            Ok((
                partial_account,
                self.reference_block.clone(),
                self.protocol_config.clone(),
                (*self.chain_mmr).clone(),
            ))
        }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            debug_assert_eq!(ref_block, self.reference_block.block_num());

            // Get foreign account inputs from RPC, retrying on transient gRPC failures.
            let account_inputs =
                (|| async { self.rpc.get_account_inputs(foreign_account_id, ref_block).await })
                    .retry(self.rpc_backoff())
                    .when(is_transient_rpc_error)
                    .notify(|err, dur| {
                        log_transient_retry("rpc.get_account_inputs", err, dur);
                    })
                    .await
                    .map_err(|err| {
                        DataStoreError::other_with_source("failed to get account inputs", err)
                    })?;

            // Ensure foreign account procedures are available to the executor via the mast store.
            // This assumes the code was not loaded from before
            self.mast_store.load_account_code(account_inputs.code());

            // Register slot names from the foreign account for later use.
            self.register_storage_map_slots(foreign_account_id, account_inputs.storage().header());

            Ok(account_inputs)
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        _vault_root: Word,
        vault_keys: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            let ref_block = self.reference_block.block_num();

            // Get vault asset witnesses from RPC, retrying on transient gRPC failures.
            let witnesses = (|| {
                let vault_keys = vault_keys.clone();
                async move {
                    self.rpc
                        .get_vault_asset_witnesses(account_id, vault_keys, Some(ref_block))
                        .await
                }
            })
            .retry(self.rpc_backoff())
            .when(is_transient_rpc_error)
            .notify(|err, dur| {
                log_transient_retry("rpc.get_vault_asset_witnesses", err, dur);
            })
            .await
            .map_err(|err| {
                DataStoreError::other_with_source("failed to get vault asset witnesses", err)
            })?;

            Ok(witnesses)
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            // The slot name that corresponds to the given account ID and map root must have been
            // registered during previous calls of this data store.
            let slot_name = {
                let storage_slots = self.storage_slots.lock().expect("storage slots lock poisoned");
                let Some(slot_name) = storage_slots.get(&(account_id, map_root)) else {
                    return Err(DataStoreError::other(
                        "requested storage slot has not been registered",
                    ));
                };
                slot_name.clone()
            };

            let ref_block = self.reference_block.block_num();

            // Get storage map witness from RPC, retrying on transient gRPC failures.
            let witness = (|| {
                let slot_name = slot_name.clone();
                async move {
                    self.rpc
                        .get_storage_map_witness(account_id, slot_name, map_key, Some(ref_block))
                        .await
                }
            })
            .retry(self.rpc_backoff())
            .when(is_transient_rpc_error)
            .notify(|err, dur| {
                log_transient_retry("rpc.get_storage_map_witness", err, dur);
            })
            .await
            .map_err(|err| {
                DataStoreError::other_with_source("failed to get storage map witness", err)
            })?;

            Ok(witness)
        }
    }

    /// Retrieves a note script by its root hash.
    ///
    /// Uses a 3-tier lookup strategy:
    /// 1. In-memory LRU cache.
    /// 2. Local SQLite database.
    /// 3. Remote RPC via gRPC.
    fn get_note_script(
        &self,
        script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move {
            let script_root = Word::from(script_root);
            // 1. In-memory LRU cache.
            if let Some(cached_script) = self.script_cache.get(&script_root) {
                return Ok(Some(cached_script));
            }

            // 2. Local DB.
            if let Some(script) = self.db.lookup_note_script(script_root).await.map_err(|err| {
                DataStoreError::other_with_source("failed to look up note script in local DB", err)
            })? {
                self.script_cache.put(script_root, script.clone());
                return Ok(Some(script));
            }

            // 3. Remote RPC, retrying on transient gRPC failures.
            let maybe_script = (|| async { self.rpc.get_note_script_by_root(script_root).await })
                .retry(self.rpc_backoff())
                .when(is_transient_rpc_error)
                .notify(|err, dur| {
                    log_transient_retry("rpc.get_note_script_by_root", err, dur);
                })
                .await
                .map_err(|err| {
                    DataStoreError::other_with_source(
                        "failed to retrieve note script from RPC",
                        err,
                    )
                })?;

            if let Some(script) = maybe_script {
                // Collect for later persistence by the coordinator.
                self.fetched_scripts
                    .lock()
                    .expect("fetched scripts lock poisoned")
                    .push((script_root, script.clone()));
                self.script_cache.put(script_root, script.clone());
                Ok(Some(script))
            } else {
                Ok(None)
            }
        }
    }
}

impl MastForestStore for NtxDataStore {
    fn get(&self, procedure_hash: &miden_protocol::Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::error::Error;
    use std::future::ready;

    use miden_protocol::errors::ProtocolConfigError;
    use miden_protocol::note::Note;
    use miden_tx::{FailedNote, TransactionExecutorError, TransactionProverError};

    use super::{
        NtxError,
        RpcError,
        SponsoredFeatureNote,
        is_transient_rpc_error,
        is_transient_status,
        partition_cycle_limited,
        retry_sponsored_notes,
        retry_variants,
        should_record_failure,
    };
    use crate::test_utils::{
        mock_network_account_id,
        mock_single_target_note,
        mock_sponsorship_note,
        mock_sponsorship_note_with_amount,
    };

    fn sponsored_note_with_two_sponsorships() -> SponsoredFeatureNote {
        let account_id = mock_network_account_id();
        let feature = mock_single_target_note(account_id, 1);
        let feature_id = feature.as_note().id();
        let sponsorships = vec![
            mock_sponsorship_note_with_amount(account_id, feature_id, 2, 1),
            mock_sponsorship_note_with_amount(account_id, feature_id, 3, 100),
        ];
        SponsoredFeatureNote { feature, sponsorships }
    }

    #[test]
    fn retry_variants_preserve_sponsorship_order() {
        let sponsored = sponsored_note_with_two_sponsorships();
        let variants = retry_variants(&sponsored, &BTreeSet::new());

        assert_eq!(variants.iter().map(Vec::len).collect::<Vec<_>>(), [3, 2, 1]);
        assert!(variants.iter().all(|variant| {
            variant.iter().any(|note| note.id() == sponsored.feature.as_note().id())
        }));
        assert_eq!(variants[0][1].id(), sponsored.sponsorships[0].id());
        assert_eq!(variants[0][2].id(), sponsored.sponsorships[1].id());
        assert_eq!(variants[1][1].id(), sponsored.sponsorships[0].id());
    }

    #[test]
    fn retry_variants_do_nothing_when_feature_is_proven() {
        let sponsored = sponsored_note_with_two_sponsorships();
        let successful =
            BTreeSet::from([sponsored.feature.as_note().id(), sponsored.sponsorships[0].id()]);
        let variants = retry_variants(&sponsored, &successful);

        assert!(variants.is_empty());
    }

    #[tokio::test]
    async fn retry_sponsored_notes_recovers_pair_from_poisoned_batch() {
        let account_id = mock_network_account_id();
        let feature_0 = mock_single_target_note(account_id, 10);
        let sponsorship_0 = mock_sponsorship_note(account_id, feature_0.as_note().id(), 11);
        let feature_1 = mock_single_target_note(account_id, 12);
        let sponsored_notes = vec![
            SponsoredFeatureNote {
                feature: feature_0.clone(),
                sponsorships: vec![sponsorship_0.clone()],
            },
            SponsoredFeatureNote { feature: feature_1, sponsorships: vec![] },
        ];
        let intact_ids = BTreeSet::from([feature_0.as_note().id(), sponsorship_0.id()]);

        // Model the exact-set result established by the protocol test: the pair succeeds by itself,
        // while adding the uncovered second feature poisons the complete batch.
        let recovered = retry_sponsored_notes(&sponsored_notes, vec![], |trial: Vec<Note>| {
            let trial_ids = trial.iter().map(Note::id).collect::<BTreeSet<_>>();
            ready(Ok::<_, NtxError>((trial_ids == intact_ids).then_some(trial)))
        })
        .await
        .unwrap();

        assert_eq!(recovered.iter().map(Note::id).collect::<BTreeSet<_>>(), intact_ids);
    }

    #[test]
    fn successful_feature_suppresses_its_sponsorship_failures() {
        let sponsored = sponsored_note_with_two_sponsorships();
        let feature_id = sponsored.feature.as_note().id();
        let sponsorship_id = sponsored.sponsorships[0].id();
        let sponsor_to_feature = HashMap::from([(sponsorship_id, feature_id)]);

        assert!(should_record_failure(sponsorship_id, &BTreeSet::new(), &sponsor_to_feature,));

        let successful = BTreeSet::from([feature_id]);
        assert!(!should_record_failure(sponsorship_id, &successful, &sponsor_to_feature,));
        assert!(!should_record_failure(feature_id, &successful, &sponsor_to_feature));
    }

    /// `partition_cycle_limited` must route notes carrying a cycle count (`num_cycles = Some`) into
    /// the cycle-limited bucket (which is then isolation-re-checked) and notes without one
    /// (`num_cycles = None`) into the genuine-failure bucket. A misclassification here would either
    /// skip the oversized re-check for a note that needs it or wrongly re-check a genuine failure.
    #[test]
    fn partition_cycle_limited_splits_on_cycle_count() {
        let account_id = mock_network_account_id();
        let cycle_limited_note = mock_single_target_note(account_id, 1).into_note();
        let genuine_note = mock_single_target_note(account_id, 2).into_note();
        let cycle_limited_id = cycle_limited_note.id();
        let genuine_id = genuine_note.id();

        let err = || TransactionExecutorError::AccountUpdateCommitment("test error");
        let failed = vec![
            // Dropped because a per-tx cycle budget was exhausted: carries a cycle count.
            FailedNote::new(cycle_limited_note, err(), Some(1234)),
            // A genuine consumability failure: no cycle count.
            FailedNote::new(genuine_note, err(), None),
        ];

        let (cycle_limited, genuine) = partition_cycle_limited(failed);

        assert_eq!(cycle_limited.len(), 1, "exactly the cycle-limited note must be re-checked");
        assert_eq!(cycle_limited[0].note().id(), cycle_limited_id);
        assert_eq!(genuine.len(), 1, "exactly the genuine failure must be penalized directly");
        assert_eq!(genuine[0].note().id(), genuine_id);
    }

    #[test]
    fn transient_status_classifies_transport_codes() {
        let transient = [
            tonic::Status::unavailable("u"),
            tonic::Status::deadline_exceeded("d"),
            tonic::Status::cancelled("c"),
            tonic::Status::aborted("a"),
            tonic::Status::unknown("u"),
            tonic::Status::internal("i"),
            tonic::Status::resource_exhausted("r"),
        ];
        for s in &transient {
            assert!(is_transient_status(s), "{:?} should be transient", s.code());
        }

        let terminal = [
            tonic::Status::invalid_argument("ia"),
            tonic::Status::failed_precondition("fp"),
            tonic::Status::out_of_range("oor"),
            tonic::Status::not_found("nf"),
            tonic::Status::already_exists("ae"),
            tonic::Status::unauthenticated("ua"),
            tonic::Status::permission_denied("pd"),
            tonic::Status::unimplemented("ui"),
            tonic::Status::data_loss("dl"),
        ];
        for s in &terminal {
            assert!(!is_transient_status(s), "{:?} should be terminal", s.code());
        }
    }

    #[test]
    fn transient_rpc_error_only_for_transient_grpc() {
        let transient = RpcError::GrpcClientError(tonic::Status::unavailable("down"));
        assert!(is_transient_rpc_error(&transient));

        let terminal_grpc = RpcError::GrpcClientError(tonic::Status::invalid_argument("bad input"));
        assert!(!is_transient_rpc_error(&terminal_grpc));

        let non_grpc = RpcError::Deserialize(
            miden_protocol::utils::serde::DeserializationError::InvalidValue("bad".into()),
        );
        assert!(!is_transient_rpc_error(&non_grpc));
    }

    /// Smoke-test that the predicates used by the request-level retry wrappers compile and select
    /// the expected variants. Prover transport failures live behind `Other` only.
    #[test]
    fn prover_other_is_the_retried_variant() {
        let err = TransactionProverError::other("remote prover unreachable");
        assert!(matches!(err, TransactionProverError::Other { .. }));
    }

    #[test]
    fn protocol_config_error_preserves_its_typed_source() {
        let error = NtxError::ProtocolConfig(ProtocolConfigError::MinimumSecurityBitsMustBeNonZero);

        assert!(
            error
                .source()
                .is_some_and(|source| source.downcast_ref::<ProtocolConfigError>().is_some())
        );
    }
}
