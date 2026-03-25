pub mod candidate;
mod execute;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use candidate::TransactionCandidate;
use futures::FutureExt;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountDelta};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_remote_prover_client::RemoteTransactionProver;
use miden_tx::FailedNote;
use tokio::sync::{Notify, RwLock, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::NoteError;
use crate::chain_state::ChainState;
use crate::clients::{BlockProducerClient, StoreClient, ValidatorClient};
use crate::db::Db;

// ACTOR REQUESTS
// ================================================================================================

/// A request sent from an account actor to the coordinator via a shared mpsc channel.
pub enum ActorRequest {
    /// One or more notes failed during transaction execution and should have their attempt
    /// counters incremented. The actor waits for the coordinator to acknowledge the DB write via
    /// the oneshot channel, preventing race conditions where the actor could re-select the same
    /// notes before the failure is persisted.
    NotesFailed {
        failed_notes: Vec<(Nullifier, NoteError)>,
        block_num: BlockNumber,
        ack_tx: tokio::sync::oneshot::Sender<()>,
    },
    /// A note script was fetched from the remote store and should be persisted to the local DB.
    CacheNoteScript { script_root: Word, script: NoteScript },
}

// ACCOUNT ACTOR CONFIG
// ================================================================================================

/// Contains miscellaneous resources that are required by all account actors.
#[derive(Clone)]
pub struct AccountActorContext {
    /// Client for interacting with the store in order to load account state.
    pub store: StoreClient,
    /// Client for interacting with the block producer.
    pub block_producer: BlockProducerClient,
    /// Client for interacting with the validator.
    pub validator: ValidatorClient,
    /// Client for remote transaction proving. If `None`, transactions will be proven locally,
    /// which is undesirable due to the performance impact.
    pub prover: Option<RemoteTransactionProver>,
    /// The latest chain state that account all actors can rely on. A single chain state is shared
    /// among all actors.
    pub chain_state: Arc<RwLock<ChainState>>,
    /// Shared LRU cache for storing retrieved note scripts to avoid repeated store calls.
    /// This cache is shared across all account actors to maximize cache efficiency.
    pub script_cache: LruCache<Word, NoteScript>,
    /// Maximum number of notes per transaction.
    pub max_notes_per_tx: NonZeroUsize,
    /// Maximum number of note execution attempts before dropping a note.
    pub max_note_attempts: usize,
    /// Duration after which an idle actor will deactivate.
    pub idle_timeout: Duration,
    /// Database for persistent state.
    pub db: Db,
    /// Channel for sending requests to the coordinator (via the builder event loop).
    pub request_tx: mpsc::Sender<ActorRequest>,
    /// Maximum number of VM execution cycles for network transactions.
    pub max_cycles: u32,
}

#[cfg(test)]
impl AccountActorContext {
    /// Creates a minimal `AccountActorContext` suitable for unit tests.
    ///
    /// The URLs are fake and actors spawned with this context will fail on their first gRPC call,
    /// but this is sufficient for testing coordinator logic (registry, deactivation, etc.).
    pub fn test(db: &crate::db::Db) -> Self {
        use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};
        use tokio::sync::RwLock;
        use url::Url;

        use crate::chain_state::ChainState;
        use crate::clients::StoreClient;
        use crate::test_utils::mock_block_header;

        let url = Url::parse("http://127.0.0.1:1").unwrap();
        let block_header = mock_block_header(0_u32.into());
        let chain_mmr = PartialMmr::from_peaks(MmrPeaks::new(Forest::new(0), vec![]).unwrap());
        let chain_state = Arc::new(RwLock::new(ChainState::new(block_header, chain_mmr)));
        let (request_tx, _request_rx) = mpsc::channel(1);

        Self {
            block_producer: BlockProducerClient::new(url.clone()),
            validator: ValidatorClient::new(url.clone()),
            prover: None,
            chain_state,
            store: StoreClient::new(url),
            script_cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
            max_notes_per_tx: NonZeroUsize::new(1).unwrap(),
            max_note_attempts: 1,
            idle_timeout: Duration::from_secs(60),
            db: db.clone(),
            request_tx,
            max_cycles: 1 << 16,
        }
    }
}

// ACCOUNT ORIGIN
// ================================================================================================

/// The origin of the account which the actor will use to initialize the account state.
#[derive(Debug)]
pub enum AccountOrigin {
    /// Accounts that have just been created by a transaction but have not been committed to the
    /// store yet.
    Transaction(Box<Account>),
    /// Accounts that already exist in the store.
    Store(NetworkAccountId),
}

impl AccountOrigin {
    /// Returns an [`AccountOrigin::Transaction`] if the account is a network account.
    pub fn transaction(delta: &AccountDelta) -> Option<Self> {
        let account = Account::try_from(delta).ok()?;
        if account.is_network() {
            Some(AccountOrigin::Transaction(account.clone().into()))
        } else {
            None
        }
    }

    /// Returns an [`AccountOrigin::Store`].
    pub fn store(account_id: NetworkAccountId) -> Self {
        AccountOrigin::Store(account_id)
    }

    /// Returns the [`NetworkAccountId`] of the account.
    pub fn id(&self) -> NetworkAccountId {
        match self {
            AccountOrigin::Transaction(account) => NetworkAccountId::try_from(account.id())
                .expect("actor accounts are always network accounts"),
            AccountOrigin::Store(account_id) => *account_id,
        }
    }
}

// ACTOR MODE
// ================================================================================================

/// The mode of operation that the account actor is currently performing.
#[derive(Debug)]
enum ActorMode {
    NoViableNotes,
    NotesAvailable,
    TransactionInflight(TransactionId),
}

// ACCOUNT ACTOR
// ================================================================================================

/// A long-running asynchronous task that handles the complete lifecycle of network transaction
/// processing. Each actor operates independently and is managed by a single coordinator that
/// spawns, monitors, and messages all actors.
///
/// ## Core Responsibilities
///
/// - **State Management**: Queries the database for the current state of network accounts,
///   including available notes and the latest account state.
/// - **Transaction Selection**: Selects viable notes and constructs a [`TransactionCandidate`]
///   based on current chain state and DB queries.
/// - **Transaction Execution**: Executes selected transactions using either local or remote
///   proving.
/// - **Mempool Integration**: Listens for mempool events to stay synchronized with the network
///   state and adjust behavior based on transaction confirmations.
///
/// ## Lifecycle
///
/// 1. **Initialization**: Checks DB for available notes to determine initial mode.
/// 2. **Event Loop**: Continuously processes mempool events and executes transactions.
/// 3. **Transaction Processing**: Selects, executes, and proves transactions, and submits them to
///    block producer.
/// 4. **State Updates**: Event effects are persisted to DB by the coordinator before actors are
///    notified.
/// 5. **Shutdown**: Terminates gracefully when cancelled or encounters unrecoverable errors.
///
/// ## Concurrency
///
/// Each actor runs in its own async task and communicates with other system components through
/// channels and shared state. The actor uses a cancellation token for graceful shutdown
/// coordination.
pub struct AccountActor {
    origin: AccountOrigin,
    store: StoreClient,
    db: Db,
    mode: ActorMode,
    notify: Arc<Notify>,
    cancel_token: CancellationToken,
    block_producer: BlockProducerClient,
    validator: ValidatorClient,
    prover: Option<RemoteTransactionProver>,
    chain_state: Arc<RwLock<ChainState>>,
    script_cache: LruCache<Word, NoteScript>,
    /// Maximum number of notes per transaction.
    max_notes_per_tx: NonZeroUsize,
    /// Maximum number of note execution attempts before dropping a note.
    max_note_attempts: usize,
    /// Duration after which an idle actor will deactivate.
    idle_timeout: Duration,
    /// Channel for sending requests to the coordinator.
    request_tx: mpsc::Sender<ActorRequest>,
    /// Maximum number of VM execution cycles for network transactions.
    max_cycles: u32,
}

impl AccountActor {
    /// Constructs a new account actor with the given configuration.
    pub fn new(
        origin: AccountOrigin,
        actor_context: &AccountActorContext,
        notify: Arc<Notify>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            origin,
            store: actor_context.store.clone(),
            db: actor_context.db.clone(),
            mode: ActorMode::NoViableNotes,
            notify,
            cancel_token,
            block_producer: actor_context.block_producer.clone(),
            validator: actor_context.validator.clone(),
            prover: actor_context.prover.clone(),
            chain_state: actor_context.chain_state.clone(),
            script_cache: actor_context.script_cache.clone(),
            max_notes_per_tx: actor_context.max_notes_per_tx,
            max_note_attempts: actor_context.max_note_attempts,
            idle_timeout: actor_context.idle_timeout,
            request_tx: actor_context.request_tx.clone(),
            max_cycles: actor_context.max_cycles,
        }
    }

    /// Runs the account actor, processing events and managing state until shutdown.
    ///
    /// The return value signals the shutdown category to the coordinator:
    ///
    /// - `Ok(())`: intentional shutdown (idle timeout, cancellation, or account removal).
    /// - `Err(_)`: crash (database error, semaphore failure, or any other bug).
    pub async fn run(mut self, semaphore: Arc<Semaphore>) -> anyhow::Result<()> {
        let account_id = self.origin.id();

        // Determine initial mode by checking DB for available notes.
        let block_num = self.chain_state.read().await.chain_tip_header.block_num();
        let has_notes = self
            .db
            .has_available_notes(account_id, block_num, self.max_note_attempts)
            .await
            .context("failed to check for available notes")?;

        if has_notes {
            self.mode = ActorMode::NotesAvailable;
        }

        loop {
            // Enable or disable transaction execution based on actor mode.
            let tx_permit_acquisition = match self.mode {
                // Disable transaction execution.
                ActorMode::NoViableNotes | ActorMode::TransactionInflight(_) => {
                    std::future::pending().boxed()
                },
                // Enable transaction execution.
                ActorMode::NotesAvailable => semaphore.acquire().boxed(),
            };

            // Idle timeout timer: only ticks when in NoViableNotes mode.
            // Mode changes cause the next loop iteration to create a fresh sleep or pending.
            let idle_timeout_sleep = match self.mode {
                ActorMode::NoViableNotes => tokio::time::sleep(self.idle_timeout).boxed(),
                _ => std::future::pending().boxed(),
            };

            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    return Ok(());
                }
                // Handle coordinator notifications. On notification, re-evaluate state from DB.
                _ = self.notify.notified() => {
                    match self.mode {
                        ActorMode::TransactionInflight(awaited_id) => {
                            // Check DB: is the inflight tx still pending?
                            let exists = self
                                .db
                                .transaction_exists(awaited_id)
                                .await
                                .context("failed to check transaction status")?;
                            if exists {
                                self.mode = ActorMode::NotesAvailable;
                            }
                        },
                        _ => {
                            self.mode = ActorMode::NotesAvailable;
                        }
                    }
                },
                // Execute transactions.
                permit = tx_permit_acquisition => {
                    let _permit = permit.context("semaphore closed")?;

                    // Read the chain state.
                    let chain_state = self.chain_state.read().await.clone();

                    // Query DB for latest account and available notes.
                    let tx_candidate = self.select_candidate_from_db(
                        account_id,
                        chain_state,
                    ).await?;

                    if let Some(tx_candidate) = tx_candidate {
                        self.execute_transactions(account_id, tx_candidate).await;
                    } else {
                        // No transactions to execute, wait for events.
                        self.mode = ActorMode::NoViableNotes;
                    }
                }
                // Idle timeout: actor has been idle too long, deactivate account.
                _ = idle_timeout_sleep => {
                    tracing::info!(%account_id, "Account actor deactivated due to idle timeout");
                    return Ok(());
                }
            }
        }
    }

    /// Selects a transaction candidate by querying the DB.
    async fn select_candidate_from_db(
        &self,
        account_id: NetworkAccountId,
        chain_state: ChainState,
    ) -> anyhow::Result<Option<TransactionCandidate>> {
        let block_num = chain_state.chain_tip_header.block_num();
        let max_notes = self.max_notes_per_tx.get();

        let (latest_account, notes) = self
            .db
            .select_candidate(account_id, block_num, self.max_note_attempts)
            .await
            .context("failed to query DB for transaction candidate")?;

        let Some(account) = latest_account else {
            tracing::info!(account_id = %account_id, "Account no longer exists in DB");
            return Ok(None);
        };

        let notes: Vec<_> = notes.into_iter().take(max_notes).collect();
        if notes.is_empty() {
            return Ok(None);
        }

        let (chain_tip_header, chain_mmr) = chain_state.into_parts();
        Ok(Some(TransactionCandidate {
            account,
            notes,
            chain_tip_header,
            chain_mmr,
        }))
    }

    /// Execute a transaction candidate and mark notes as failed as required.
    ///
    /// Updates the state of the actor based on the execution result.
    #[tracing::instrument(name = "ntx.actor.execute_transactions", skip(self, tx_candidate))]
    async fn execute_transactions(
        &mut self,
        account_id: NetworkAccountId,
        tx_candidate: TransactionCandidate,
    ) {
        let block_num = tx_candidate.chain_tip_header.block_num();

        // Execute the selected transaction.
        let context = execute::NtxContext::new(
            self.block_producer.clone(),
            self.validator.clone(),
            self.prover.clone(),
            self.store.clone(),
            self.script_cache.clone(),
            self.db.clone(),
            self.max_cycles,
        );

        let notes = tx_candidate.notes.clone();
        let account_id = tx_candidate.account.id();
        let note_ids: Vec<_> = notes.iter().map(|n| n.to_inner().as_note().id()).collect();
        tracing::info!(
            %account_id,
            ?note_ids,
            num_notes = notes.len(),
            "executing network transaction",
        );

        let execution_result = context.execute_transaction(tx_candidate).await;
        match execution_result {
            Ok((tx_id, failed, scripts_to_cache)) => {
                tracing::info!(
                    %account_id,
                    %tx_id,
                    num_failed = failed.len(),
                    "network transaction executed with some failed notes",
                );
                self.cache_note_scripts(scripts_to_cache).await;
                if !failed.is_empty() {
                    let failed_notes = log_failed_notes(failed);
                    self.mark_notes_failed(&failed_notes, block_num).await;
                }
                self.mode = ActorMode::TransactionInflight(tx_id);
            },
            // Transaction execution failed.
            Err(err) => {
                let error_msg = err.as_report();
                tracing::error!(
                    %account_id,
                    ?note_ids,
                    err = %error_msg,
                    "network transaction failed",
                );
                self.mode = ActorMode::NoViableNotes;

                // For `AllNotesFailed`, use the per-note errors which contain the
                // specific reason each note failed (e.g. consumability check details).
                let failed_notes: Vec<_> = match err {
                    execute::NtxError::AllNotesFailed(per_note) => log_failed_notes(per_note),
                    other => {
                        let error: NoteError = Arc::new(other);
                        notes
                            .iter()
                            .map(|note| {
                                tracing::info!(
                                    note.id = %note.to_inner().as_note().id(),
                                    nullifier = %note.nullifier(),
                                    err = %error_msg,
                                    "note failed: transaction execution error",
                                );
                                (note.nullifier(), error.clone())
                            })
                            .collect()
                    },
                };
                self.mark_notes_failed(&failed_notes, block_num).await;
            },
        }
    }

    /// Sends requests to the coordinator to cache note scripts fetched from the remote store.
    async fn cache_note_scripts(&self, scripts: Vec<(Word, NoteScript)>) {
        for (script_root, script) in scripts {
            if self
                .request_tx
                .send(ActorRequest::CacheNoteScript { script_root, script })
                .await
                .is_err()
            {
                break;
            }
        }
    }

    /// Sends a request to the coordinator to mark notes as failed and waits for the DB write to
    /// complete. This prevents a race condition where the actor could re-select the same notes
    /// before the failure counts are updated in the database.
    async fn mark_notes_failed(
        &self,
        failed_notes: &[(Nullifier, NoteError)],
        block_num: BlockNumber,
    ) {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if self
            .request_tx
            .send(ActorRequest::NotesFailed {
                failed_notes: failed_notes.to_vec(),
                block_num,
                ack_tx,
            })
            .await
            .is_err()
        {
            return;
        }
        // Wait for the coordinator to confirm the DB write.
        let _ = ack_rx.await;
    }
}

/// Logs each failed note and returns a vec of `(nullifier, error)` pairs.
fn log_failed_notes(failed: Vec<FailedNote>) -> Vec<(Nullifier, NoteError)> {
    failed
        .into_iter()
        .map(|f| {
            let error_msg = f.error.as_report();
            tracing::info!(
                note.id = %f.note.id(),
                nullifier = %f.note.nullifier(),
                err = %error_msg,
                "note failed: consumability check",
            );
            (f.note.nullifier(), Arc::new(f.error) as NoteError)
        })
        .collect()
}
