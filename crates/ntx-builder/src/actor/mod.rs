pub mod candidate;
mod execute;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use candidate::TransactionCandidate;
use futures::FutureExt;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountDelta};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_remote_prover_client::RemoteTransactionProver;
use tokio::sync::{AcquireError, Notify, RwLock, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::chain_state::ChainState;
use crate::clients::{BlockProducerClient, StoreClient};
use crate::db::Db;

/// Converts a database result into an `ActorShutdownReason` error, logging the error on failure.
fn db_query<T>(
    account_id: NetworkAccountId,
    result: Result<T, miden_node_db::DatabaseError>,
    context: &str,
) -> Result<T, ActorShutdownReason> {
    result.map_err(|err| {
        tracing::error!(err = err.as_report(), account_id = %account_id, "{context}");
        ActorShutdownReason::DbError(account_id)
    })
}

// ACTOR REQUESTS
// ================================================================================================

/// A request sent from an account actor to the coordinator via a shared mpsc channel.
pub enum ActorRequest {
    /// One or more notes failed during transaction execution and should have their attempt
    /// counters incremented. The actor waits for the coordinator to acknowledge the DB write via
    /// the oneshot channel, preventing race conditions where the actor could re-select the same
    /// notes before the failure is persisted.
    NotesFailed {
        nullifiers: Vec<Nullifier>,
        block_num: BlockNumber,
        ack_tx: tokio::sync::oneshot::Sender<()>,
    },
    /// A note script was fetched from the remote store and should be persisted to the local DB.
    CacheNoteScript { script_root: Word, script: NoteScript },
}

// ACTOR SHUTDOWN REASON
// ================================================================================================

/// The reason an actor has shut down.
pub enum ActorShutdownReason {
    /// Occurs when an account actor detects failure in acquiring the rate-limiting semaphore.
    SemaphoreFailed(AcquireError),
    /// Occurs when an account actor detects its corresponding cancellation token has been triggered
    /// by the coordinator. Cancellation tokens are triggered by the coordinator to initiate
    /// graceful shutdown of actors.
    Cancelled(NetworkAccountId),
    /// Occurs when the actor encounters a database error it cannot recover from.
    DbError(NetworkAccountId),
}

// ACCOUNT ACTOR CONFIG
// ================================================================================================

/// Contains miscellaneous resources that are required by all account actors.
#[derive(Clone)]
pub struct AccountActorContext {
    /// Client for interacting with the store in order to load account state.
    pub store: StoreClient,
    /// Address of the block producer gRPC server.
    pub block_producer_url: Url,
    /// Address of the Validator server.
    pub validator_url: Url,
    /// Address of the remote prover. If `None`, transactions will be proven locally, which is
    // undesirable due to the performance impact.
    pub tx_prover_url: Option<Url>,
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
    /// Database for persistent state.
    pub db: Db,
    /// Channel for sending requests to the coordinator (via the builder event loop).
    pub request_tx: mpsc::Sender<ActorRequest>,
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
    /// Channel for sending requests to the coordinator.
    request_tx: mpsc::Sender<ActorRequest>,
}

impl AccountActor {
    /// Constructs a new account actor with the given configuration.
    pub fn new(
        origin: AccountOrigin,
        actor_context: &AccountActorContext,
        notify: Arc<Notify>,
        cancel_token: CancellationToken,
    ) -> Self {
        let block_producer = BlockProducerClient::new(actor_context.block_producer_url.clone());
        let validator = Builder::new(actor_context.validator_url.clone())
            .without_tls()
            .with_timeout(Duration::from_secs(10))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>();
        let prover = actor_context.tx_prover_url.clone().map(RemoteTransactionProver::new);
        Self {
            origin,
            store: actor_context.store.clone(),
            db: actor_context.db.clone(),
            mode: ActorMode::NoViableNotes,
            notify,
            cancel_token,
            block_producer,
            validator,
            prover,
            chain_state: actor_context.chain_state.clone(),
            script_cache: actor_context.script_cache.clone(),
            max_notes_per_tx: actor_context.max_notes_per_tx,
            max_note_attempts: actor_context.max_note_attempts,
            request_tx: actor_context.request_tx.clone(),
        }
    }

    /// Runs the account actor, processing events and managing state until a reason to shutdown is
    /// encountered.
    pub async fn run(mut self, semaphore: Arc<Semaphore>) -> ActorShutdownReason {
        let account_id = self.origin.id();

        // Determine initial mode by checking DB for available notes.
        let block_num = self.chain_state.read().await.chain_tip_header.block_num();
        let has_notes = match db_query(
            account_id,
            self.db.has_available_notes(account_id, block_num, self.max_note_attempts).await,
            "failed to check for available notes",
        ) {
            Ok(v) => v,
            Err(reason) => return reason,
        };

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
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    return ActorShutdownReason::Cancelled(account_id);
                }
                // Handle coordinator notifications. On notification, re-evaluate state from DB.
                _ = self.notify.notified() => {
                    match self.mode {
                        ActorMode::TransactionInflight(awaited_id) => {
                            // Check DB: is the inflight tx still pending?
                            let exists = match db_query(
                                account_id,
                                self.db
                                    .transaction_exists(awaited_id)
                                    .await,
                                "failed to check transaction status",
                            ) {
                                Ok(v) => v,
                                Err(reason) => return reason,
                            };
                            if !exists {
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
                    match permit {
                        Ok(_permit) => {
                            // Read the chain state.
                            let chain_state = self.chain_state.read().await.clone();

                            // Query DB for latest account and available notes.
                            let tx_candidate = match self.select_candidate_from_db(
                                account_id,
                                chain_state,
                            ).await {
                                Ok(candidate) => candidate,
                                Err(shutdown_reason) => return shutdown_reason,
                            };

                            if let Some(tx_candidate) = tx_candidate {
                                self.execute_transactions(account_id, tx_candidate).await;
                            } else {
                                // No transactions to execute, wait for events.
                                self.mode = ActorMode::NoViableNotes;
                            }
                        }
                        Err(err) => {
                            return ActorShutdownReason::SemaphoreFailed(err);
                        }
                    }
                }
            }
        }
    }

    /// Selects a transaction candidate by querying the DB.
    async fn select_candidate_from_db(
        &self,
        account_id: NetworkAccountId,
        chain_state: ChainState,
    ) -> Result<Option<TransactionCandidate>, ActorShutdownReason> {
        let block_num = chain_state.chain_tip_header.block_num();
        let max_notes = self.max_notes_per_tx.get();

        let (latest_account, notes) = db_query(
            account_id,
            self.db.select_candidate(account_id, block_num, self.max_note_attempts).await,
            "failed to query DB for transaction candidate",
        )?;

        let Some(account) = latest_account else {
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
        );

        let notes = tx_candidate.notes.clone();
        let execution_result = context.execute_transaction(tx_candidate).await;
        match execution_result {
            Ok((tx_id, failed, scripts_to_cache)) => {
                self.cache_note_scripts(scripts_to_cache).await;
                if !failed.is_empty() {
                    let nullifiers: Vec<_> =
                        failed.into_iter().map(|note| note.note.nullifier()).collect();
                    self.mark_notes_failed(&nullifiers, block_num).await;
                }
                self.mode = ActorMode::TransactionInflight(tx_id);
            },
            // Transaction execution failed.
            Err(err) => {
                tracing::error!(err = err.as_report(), "network transaction failed");
                self.mode = ActorMode::NoViableNotes;
                let nullifiers: Vec<_> = notes
                    .into_iter()
                    .map(|note| Note::from(note.into_inner()).nullifier())
                    .collect();
                self.mark_notes_failed(&nullifiers, block_num).await;
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
    async fn mark_notes_failed(&self, nullifiers: &[Nullifier], block_num: BlockNumber) {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if self
            .request_tx
            .send(ActorRequest::NotesFailed {
                nullifiers: nullifiers.to_vec(),
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
