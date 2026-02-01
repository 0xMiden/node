pub mod account_state;
mod execute;
mod inflight_note;
mod note_state;

use std::sync::Arc;
use std::time::Duration;

use account_state::{NetworkAccountState, TransactionCandidate};
use futures::FutureExt;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountDelta};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::TransactionId;
use miden_remote_prover_client::remote_prover::tx_prover::RemoteTransactionProver;
use tokio::sync::{AcquireError, RwLock, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::block_producer::BlockProducerClient;
use crate::builder::ChainState;
use crate::store::StoreClient;

// ACTOR SHUTDOWN REASON
// ================================================================================================

/// The reason an actor has shut down.
pub enum ActorShutdownReason {
    /// Occurs when the transaction that created the actor is reverted.
    AccountReverted(NetworkAccountId),
    /// Occurs when an account actor detects failure in the messaging channel used by the
    /// coordinator.
    EventChannelClosed,
    /// Occurs when an account actor detects failure in acquiring the rate-limiting semaphore.
    SemaphoreFailed(AcquireError),
    /// Occurs when an account actor detects its corresponding cancellation token has been triggered
    /// by the coordinator. Cancellation tokens are triggered by the coordinator to initiate
    /// graceful shutdown of actors.
    Cancelled(NetworkAccountId),
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
/// - **State Management**: Loads and maintains the current state of network accounts, including
///   available notes, pending transactions, and account commitments.
/// - **Transaction Selection**: Selects viable notes and constructs a [`TransactionCandidate`]
///   based on current chain state.
/// - **Transaction Execution**: Executes selected transactions using either local or remote
///   proving.
/// - **Mempool Integration**: Listens for mempool events to stay synchronized with the network
///   state and adjust behavior based on transaction confirmations.
///
/// ## Lifecycle
///
/// 1. **Initialization**: Loads account state from the store or uses provided account data.
/// 2. **Event Loop**: Continuously processes mempool events and executes transactions.
/// 3. **Transaction Processing**: Selects, executes, and proves transactions, and submits them to
///    block producer.
/// 4. **State Updates**: Updates internal state based on mempool events and execution results.
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
    mode: ActorMode,
    event_rx: mpsc::Receiver<Arc<MempoolEvent>>,
    cancel_token: CancellationToken,
    block_producer: BlockProducerClient,
    validator: ValidatorClient,
    prover: Option<RemoteTransactionProver>,
    chain_state: Arc<RwLock<ChainState>>,
    script_cache: LruCache<Word, NoteScript>,
}

impl AccountActor {
    /// Constructs a new account actor and corresponding messaging channel with the given
    /// configuration.
    pub fn new(
        origin: AccountOrigin,
        actor_context: &AccountActorContext,
        event_rx: mpsc::Receiver<Arc<MempoolEvent>>,
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
            mode: ActorMode::NoViableNotes,
            event_rx,
            cancel_token,
            block_producer,
            validator,
            prover,
            chain_state: actor_context.chain_state.clone(),
            script_cache: actor_context.script_cache.clone(),
        }
    }

    /// Runs the account actor, processing events and managing state until a reason to shutdown is
    /// encountered.
    pub async fn run(mut self, semaphore: Arc<Semaphore>) -> ActorShutdownReason {
        // Load the account state from the store and set up the account actor state.
        let account = {
            match self.origin {
                AccountOrigin::Store(account_id) => self
                    .store
                    .get_network_account(account_id)
                    .await
                    .expect("actor should be able to load account")
                    .expect("actor account should exist"),
                AccountOrigin::Transaction(ref account) => *(account.clone()),
            }
        };
        let block_num = self.chain_state.read().await.chain_tip_header.block_num();
        let mut state =
            NetworkAccountState::load(account, self.origin.id(), &self.store, block_num)
                .await
                .expect("actor should be able to load account state");

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
                    return ActorShutdownReason::Cancelled(self.origin.id());
                }
                // Handle mempool events.
                event = self.event_rx.recv() => {
                    let Some(event) = event else {
                         return ActorShutdownReason::EventChannelClosed;
                    };
                    // Re-enable transaction execution if the transaction being waited on has been
                    // added to the mempool.
                    if let ActorMode::TransactionInflight(awaited_id) = self.mode {
                        if let MempoolEvent::TransactionAdded { id, .. } = *event {
                            if id == awaited_id {
                                self.mode = ActorMode::NotesAvailable;
                            }
                        }
                    } else {
                        self.mode = ActorMode::NotesAvailable;
                    }
                    // Update state.
                    if let Some(shutdown_reason) = state.mempool_update(event.as_ref()) {
                        return shutdown_reason;
                    }
                },
                // Execute transactions.
                permit = tx_permit_acquisition => {
                    match permit {
                        Ok(_permit) => {
                            // Read the chain state.
                            let chain_state = self.chain_state.read().await.clone();
                            // Find a candidate transaction and execute it.
                            if let Some(tx_candidate) = state.select_candidate(crate::MAX_NOTES_PER_TX, chain_state) {
                                self.execute_transactions(&mut state, tx_candidate).await;
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

    /// Execute a transaction candidate and mark notes as failed as required.
    ///
    /// Updates the state of the actor based on the execution result.
    #[tracing::instrument(name = "ntx.actor.execute_transactions", skip(self, state, tx_candidate))]
    async fn execute_transactions(
        &mut self,
        state: &mut NetworkAccountState,
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
        );

        let notes = tx_candidate.notes.clone();
        let execution_result = context.execute_transaction(tx_candidate).await;
        match execution_result {
            // Execution completed without failed notes.
            Ok((tx_id, failed)) if failed.is_empty() => {
                self.mode = ActorMode::TransactionInflight(tx_id);
            },
            // Execution completed with some failed notes.
            Ok((tx_id, failed)) => {
                let notes = failed.into_iter().map(|note| note.note).collect::<Vec<_>>();
                state.notes_failed(notes.as_slice(), block_num);
                self.mode = ActorMode::TransactionInflight(tx_id);
            },
            // Transaction execution failed.
            Err(err) => {
                tracing::error!(err = err.as_report(), "network transaction failed");
                self.mode = ActorMode::NoViableNotes;
                let notes =
                    notes.into_iter().map(|note| note.into_inner().into()).collect::<Vec<_>>();
                state.notes_failed(notes.as_slice(), block_num);
            },
        }
    }
}

// HELPERS
// ================================================================================================

/// Checks if the backoff block period has passed.
///
/// The number of blocks passed since the last attempt must be greater than or equal to
/// e^(0.25 * `attempt_count`) rounded to the nearest integer.
///
/// This evaluates to the following:
/// - After 1 attempt, the backoff period is 1 block.
/// - After 3 attempts, the backoff period is 2 blocks.
/// - After 10 attempts, the backoff period is 12 blocks.
/// - After 20 attempts, the backoff period is 148 blocks.
/// - etc...
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
fn has_backoff_passed(
    chain_tip: BlockNumber,
    last_attempt: Option<BlockNumber>,
    attempts: usize,
) -> bool {
    if attempts == 0 {
        return true;
    }
    // Compute the number of blocks passed since the last attempt.
    let blocks_passed = last_attempt
        .and_then(|last| chain_tip.checked_sub(last.as_u32()))
        .unwrap_or_default();

    // Compute the exponential backoff threshold: Δ = e^(0.25 * n).
    let backoff_threshold = (0.25 * attempts as f64).exp().round() as usize;

    // Check if the backoff period has passed.
    blocks_passed.as_usize() > backoff_threshold
}
