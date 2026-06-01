use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountStorageHeader,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::errors::TransactionInputError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
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
    TransactionScript,
};
use miden_protocol::vm::FutureMaybeSend;
use miden_remote_prover_client::RemoteTransactionProver;
use miden_standards::note::AccountTargetNetworkNote;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{
    DataStore,
    DataStoreError,
    ExecutionOptions,
    FailedNote,
    LocalTransactionProver,
    MastForestStore,
    NoteCheckerError,
    NoteConsumptionChecker,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionMastStore,
    TransactionProverError,
};
use tracing::{Instrument, instrument};

use crate::COMPONENT;
use crate::actor::candidate::TransactionCandidate;
use crate::clients::{RpcClient, RpcError};
use crate::db::Db;

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
    ExponentialBuilder::default()
        .with_min_delay(initial)
        .with_max_delay(max)
        .with_factor(2.0)
        .with_max_times(MAX_REQUEST_RETRIES)
        .with_jitter()
}

/// Emits a structured warning for a transient NTX request failure that is about to be retried.
fn log_transient_retry<E: std::error::Error>(operation: &'static str, err: &E, sleep: Duration) {
    tracing::warn!(
        target: COMPONENT,
        operation,
        err = %err.as_report(),
        sleep_ms = sleep.as_millis() as u64,
        "ntx transient request failure; retrying after backoff",
    );
}

/// The result of a successful transaction execution.
///
/// Contains the transaction ID, any notes that failed during filtering, and note scripts fetched
/// from the remote RPC service that should be persisted to the local DB cache.
pub type NtxExecutionResult = (TransactionId, Vec<FailedNote>, Vec<(Word, NoteScript)>);

// NETWORK TRANSACTION CONTEXT
// ================================================================================================

/// Provides the context for execution [network transaction candidates](TransactionCandidate).
#[derive(Clone)]
pub struct NtxContext {
    /// The prover to delegate proofs to.
    ///
    /// Defaults to local proving if unset. This should be avoided in production as this is
    /// computationally intensive.
    prover: Option<RemoteTransactionProver>,

    /// The RPC client for retrieving note scripts.
    rpc: RpcClient,

    /// LRU cache for storing retrieved note scripts to avoid repeated RPC calls.
    script_cache: LruCache<Word, NoteScript>,

    /// Local database for persistent note script caching.
    db: Db,

    /// Maximum number of VM execution cycles for network transactions.
    max_cycles: u32,

    /// Pre-compiled transaction script that sets the network tx's on-chain expiration delta. Cloned
    /// into the [`TransactionArgs`] of the executed transaction.
    expiration_script: TransactionScript,

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
        prover: Option<RemoteTransactionProver>,
        rpc: RpcClient,
        script_cache: LruCache<Word, NoteScript>,
        db: Db,
        max_cycles: u32,
        expiration_script: TransactionScript,
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
            expiration_script,
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
            false,
            false,
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
    /// On success, returns an [`NtxExecutionResult`] containing the transaction ID, any notes
    /// that failed during filtering, and note scripts fetched from the remote RPC service that
    /// should be persisted to the local DB cache.
    ///
    /// # Errors
    ///
    /// Returns an [`NtxError`] if any step of the pipeline fails, including:
    /// - Note filtering (e.g., all notes fail consumability checks).
    /// - Transaction execution.
    /// - Proof generation.
    /// - Submission to the network.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction", skip_all, err)]
    pub fn execute_transaction(
        self,
        tx: TransactionCandidate,
    ) -> impl FutureMaybeSend<NtxResult<NtxExecutionResult>> {
        let TransactionCandidate {
            account,
            notes,
            chain_tip_header,
            chain_mmr,
        } = tx;
        tracing::Span::current().set_attribute("account.id", account.id());
        tracing::Span::current()
            .set_attribute("account.id.network_prefix", account.id().prefix().to_string().as_str());
        tracing::Span::current().set_attribute("notes.count", notes.len());
        tracing::Span::current()
            .set_attribute("reference_block.number", chain_tip_header.block_num());

        async move {
            Box::pin(async move {
                let notes =
                    notes.into_iter().map(AccountTargetNetworkNote::into_note).collect::<Vec<_>>();

                // VM execution (note filtering + transaction execution) is CPU-intensive and may
                // not yield between await points. Run it on a dedicated blocking thread while using
                // the parent runtime handle to drive async RPC callbacks.
                let ctx = self.clone();
                let handle = tokio::runtime::Handle::current();
                let span = tracing::Span::current();

                let (executed_tx, failed_notes, scripts_to_cache) =
                    spawn_blocking_in_current_span(move || {
                        let data_store = NtxDataStore::new(
                            account,
                            chain_tip_header,
                            chain_mmr,
                            ctx.rpc.clone(),
                            ctx.script_cache.clone(),
                            ctx.db.clone(),
                            ctx.request_backoff,
                        );
                        handle.block_on(
                            async {
                                let (successful_notes, failed_notes) =
                                    ctx.filter_notes(&data_store, notes).await?;
                                let executed_tx =
                                    Box::pin(ctx.execute(&data_store, successful_notes)).await?;
                                let scripts_to_cache = data_store.take_fetched_scripts();
                                Ok::<_, NtxError>((executed_tx, failed_notes, scripts_to_cache))
                            }
                            .instrument(span),
                        )
                    })
                    .await
                    .unwrap_or_else(|err| std::panic::resume_unwind(err.into_panic()))?;

                // Prove transaction.
                let tx_inputs: TransactionInputs = executed_tx.into();
                let proven_tx = Box::pin(self.prove(&tx_inputs)).await?;

                // Submit transaction through the RPC service.
                self.submit(&proven_tx, &tx_inputs).await?;

                Ok((proven_tx.id(), failed_notes, scripts_to_cache))
            })
            .in_current_span()
            .await
            .inspect_err(|err| tracing::Span::current().set_error(err))
        }
    }

    /// Filters a collection of notes, returning only those that can be successfully executed
    /// against the given network account.
    ///
    /// This function performs a consumability check on each provided note and partitions them into
    /// two sets:
    /// - Successful notes: notes that can be executed and are returned wrapped in [`InputNotes`].
    /// - Failed notes: notes that cannot be executed.
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
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.filter_notes", skip_all, err)]
    async fn filter_notes(
        &self,
        data_store: &NtxDataStore,
        notes: Vec<Note>,
    ) -> NtxResult<(InputNotes<InputNote>, Vec<FailedNote>)> {
        let executor = self.create_executor(data_store);
        let checker = NoteConsumptionChecker::new(&executor);

        match Box::pin(checker.check_notes_consumability(
            data_store.account.id(),
            data_store.reference_block.block_num(),
            notes,
            TransactionArgs::default(),
        ))
        .await
        {
            Ok(consumption_info) => {
                let (successful, failed) = consumption_info.into_parts();
                for failed_note in &failed {
                    tracing::info!(
                        note.id = %failed_note.note().id(),
                        nullifier = %failed_note.note().nullifier(),
                        err = %failed_note.error().as_report(),
                        "note failed consumability check",
                    );
                }

                // Map successful notes to input notes.
                let successful_notes =
                    successful.into_iter().map(|s| s.note().clone()).collect::<Vec<_>>();
                let successful = InputNotes::from_unauthenticated_notes(successful_notes)
                    .map_err(NtxError::InputNotes)?;

                // If none are successful, abort.
                if successful.is_empty() {
                    return Err(NtxError::AllNotesFailed(failed));
                }

                Ok((successful, failed))
            },
            Err(err) => return Err(NtxError::NoteFilter(err)),
        }
    }

    /// Creates an executes a transaction with the network account and the given set of notes.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.execute", skip_all, err)]
    async fn execute(
        &self,
        data_store: &NtxDataStore,
        notes: InputNotes<InputNote>,
    ) -> NtxResult<ExecutedTransaction> {
        let executor = self.create_executor(data_store);

        // Attach the pre-compiled expiration script so the submitted tx is rejected on-chain if it
        // does not land within the configured block delta.
        let tx_args = TransactionArgs::default().with_tx_script(self.expiration_script.clone());

        Box::pin(executor.execute_transaction(
            data_store.account.id(),
            data_store.reference_block.block_num(),
            notes,
            tx_args,
        ))
        .await
        .map_err(NtxError::Execution)
    }

    /// Delegates the transaction proof to the remote prover if configured, otherwise performs the
    /// proof locally.
    ///
    /// Transient transport failures against the remote prover are retried in-place; intrinsic
    /// proving errors (witness rejected, malformed inputs) escape on the first attempt.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.prove", skip_all, err)]
    async fn prove(&self, tx_inputs: &TransactionInputs) -> NtxResult<ProvenTransaction> {
        if let Some(remote) = &self.prover {
            (|| async { remote.prove(tx_inputs).await })
                .retry(self.request_backoff())
                .when(|err| matches!(err, TransactionProverError::Other { .. }))
                .notify(|err, dur| {
                    log_transient_retry("remote_prover.prove", err, dur);
                })
                .await
                .map_err(NtxError::Proving)
        } else {
            // Only perform tx inputs clone for local proving.
            let tx_inputs = tx_inputs.clone();
            let span = tracing::Span::current();

            spawn_blocking_in_current_span(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build tokio runtime")
                    .block_on(LocalTransactionProver::default().prove(tx_inputs).instrument(span))
            })
            .await
            .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
            .map_err(NtxError::Proving)
        }
    }

    /// Submits the transaction through the RPC service.
    ///
    /// Transient gRPC failures (`Unavailable`, `DeadlineExceeded`, ...) are retried in-place;
    /// content-rejection codes escape on the first attempt so the actor can mark the batch failed.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.submit", skip_all, err)]
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
    account: Account,
    reference_block: BlockHeader,
    /// The chain MMR, wrapped in `Arc` to avoid expensive clones when reading the chain state.
    chain_mmr: Arc<PartialBlockchain>,
    mast_store: TransactionMastStore,
    /// RPC client for retrieving note scripts.
    rpc: RpcClient,
    /// LRU cache for storing retrieved note scripts to avoid repeated RPC calls.
    script_cache: LruCache<Word, NoteScript>,
    /// Local database for persistent note script.
    db: Db,
    /// Scripts fetched from the remote RPC service during execution, to be persisted by the
    /// coordinator.
    fetched_scripts: Arc<Mutex<Vec<(Word, NoteScript)>>>,
    /// Mapping of storage map roots to storage slot names observed during various calls.
    ///
    /// The registered slot names are subsequently used to retrieve storage map witnesses from the
    /// RPC service. We need this because the RPC interface (and the underlying SMT forest) use storage
    /// slot names, but the `DataStore` interface works with tree roots. To get around this problem
    /// we populate this map when:
    /// - The the native account is loaded (in `get_transaction_inputs()`).
    /// - When a foreign account is loaded (in `get_foreign_account_inputs`).
    ///
    /// The assumption here are:
    /// - Once an account is loaded, the mapping between `(account_id, map_root)` and slot names do
    ///   not change. This is always the case.
    /// - New storage slots created during transaction execution will not be accesses in the same
    ///   transaction. The mechanism for adding new storage slots is not implemented yet, but the
    ///   plan for it is consistent with this assumption.
    ///
    /// One nuance worth mentioning: it is possible that there could be a root collision where an
    /// account has two storage maps with the same root. In this case, the map will contain only a
    /// single entry with the storage slot name that was added last. Thus, technically, requests
    /// to the RPC service could be "wrong", but given that two identical maps have identical witnesses
    /// this does not cause issues in practice.
    storage_slots: Arc<Mutex<HashMap<(AccountId, Word), StorageSlotName>>>,
    /// Per-request retry backoff for transient RPC failures.
    request_backoff: ExponentialBuilder,
}

impl NtxDataStore {
    /// Creates a new `NtxDataStore` with default cache size.
    fn new(
        account: Account,
        reference_block: BlockHeader,
        chain_mmr: Arc<PartialBlockchain>,
        rpc: RpcClient,
        script_cache: LruCache<Word, NoteScript>,
        db: Db,
        request_backoff: ExponentialBuilder,
    ) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(account.code());

        Self {
            account,
            reference_block,
            chain_mmr,
            mast_store,
            rpc,
            script_cache,
            db,
            fetched_scripts: Arc::new(Mutex::new(Vec::new())),
            storage_slots: Arc::new(Mutex::new(HashMap::default())),
            request_backoff,
        }
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
    ) -> impl FutureMaybeSend<Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError>>
    {
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

            let partial_account = PartialAccount::from(&self.account);
            Ok((partial_account, self.reference_block.clone(), (*self.chain_mmr).clone()))
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
        vault_keys: BTreeSet<AssetVaultKey>,
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
    fn get(
        &self,
        procedure_hash: &miden_protocol::Word,
    ) -> Option<std::sync::Arc<miden_protocol::MastForest>> {
        self.mast_store.get(procedure_hash)
    }
}

#[cfg(test)]
mod tests {
    use miden_tx::TransactionProverError;

    use super::{RpcError, is_transient_rpc_error, is_transient_status};

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
}
