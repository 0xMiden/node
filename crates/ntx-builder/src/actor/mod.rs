pub(crate) mod account_effect;
pub mod account_state;
mod execute;
pub(crate) mod inflight_note;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use account_state::TransactionCandidate;
use futures::FutureExt;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountDelta};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteScript};
use miden_protocol::transaction::TransactionId;
use miden_remote_prover_client::RemoteTransactionProver;
use tokio::sync::{AcquireError, RwLock, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::block_producer::BlockProducerClient;
use crate::builder::ChainState;
use crate::db::Db;
use crate::store::StoreClient;

// ACTOR SHUTDOWN REASON
// ================================================================================================

/// The reason an actor has shut down.
pub enum ActorShutdownReason {
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
    /// Maximum number of notes per transaction.
    pub max_notes_per_tx: NonZeroUsize,
    /// Maximum number of note execution attempts before dropping a note.
    pub max_note_attempts: usize,
    /// Database for persistent state.
    pub db: Db,
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
    event_rx: mpsc::Receiver<Arc<MempoolEvent>>,
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
            db: actor_context.db.clone(),
            mode: ActorMode::NoViableNotes,
            event_rx,
            cancel_token,
            block_producer,
            validator,
            prover,
            chain_state: actor_context.chain_state.clone(),
            script_cache: actor_context.script_cache.clone(),
            max_notes_per_tx: actor_context.max_notes_per_tx,
            max_note_attempts: actor_context.max_note_attempts,
        }
    }

    /// Runs the account actor, processing events and managing state until a reason to shutdown is
    /// encountered.
    pub async fn run(mut self, semaphore: Arc<Semaphore>) -> ActorShutdownReason {
        let account_id = self.origin.id();

        // Determine initial mode by checking DB for available notes.
        let block_num = self.chain_state.read().await.chain_tip_header.block_num();
        let has_notes = self
            .db
            .has_available_notes(account_id, block_num, self.max_note_attempts)
            .await
            .expect("actor should be able to check for available notes");

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
                // Handle mempool events.
                event = self.event_rx.recv() => {
                    let Some(event) = event else {
                         return ActorShutdownReason::EventChannelClosed;
                    };
                    // Re-enable transaction execution if the transaction being waited on has
                    // been resolved (added to mempool, committed in a block, or reverted).
                    if let ActorMode::TransactionInflight(awaited_id) = self.mode {
                        let should_wake = match event.as_ref() {
                            MempoolEvent::TransactionAdded { id, .. } => *id == awaited_id,
                            MempoolEvent::BlockCommitted { txs, .. } => {
                                txs.contains(&awaited_id)
                            },
                            MempoolEvent::TransactionsReverted(tx_ids) => {
                                tx_ids.contains(&awaited_id)
                            },
                        };
                        if should_wake {
                            self.mode = ActorMode::NotesAvailable;
                        }
                    } else {
                        self.mode = ActorMode::NotesAvailable;
                    }
                },
                // Execute transactions.
                permit = tx_permit_acquisition => {
                    match permit {
                        Ok(_permit) => {
                            // Read the chain state.
                            let chain_state = self.chain_state.read().await.clone();

                            // Drop notes that have failed too many times.
                            if let Err(err) = self.db.drop_failing_notes(account_id, self.max_note_attempts).await {
                                tracing::error!(err = %err, "failed to drop failing notes");
                            }

                            // Query DB for latest account and available notes.
                            let tx_candidate = self.select_candidate_from_db(
                                account_id,
                                chain_state,
                            ).await;

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
    ) -> Option<TransactionCandidate> {
        let block_num = chain_state.chain_tip_header.block_num();
        let max_notes = self.max_notes_per_tx.get();

        let (latest_account, notes) = self
            .db
            .select_candidate(account_id, block_num, self.max_note_attempts)
            .await
            .expect("actor should be able to query DB for candidate");

        let account = latest_account?;

        let notes: Vec<_> = notes.into_iter().take(max_notes).collect();
        if notes.is_empty() {
            return None;
        }

        let (chain_tip_header, chain_mmr) = chain_state.into_parts();
        Some(TransactionCandidate {
            account,
            notes,
            chain_tip_header,
            chain_mmr,
        })
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
                let nullifiers: Vec<_> =
                    failed.into_iter().map(|note| note.note.nullifier()).collect();
                self.mark_notes_failed(&nullifiers, block_num).await;
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

    /// Marks notes as failed in the DB.
    async fn mark_notes_failed(
        &self,
        nullifiers: &[miden_protocol::note::Nullifier],
        block_num: BlockNumber,
    ) {
        if let Err(err) = self.db.notes_failed(nullifiers.to_vec(), block_num).await {
            tracing::error!(err = %err, "failed to mark notes as failed");
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

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    use super::has_backoff_passed;

    #[rstest::rstest]
    #[test]
    #[case::all_zero(Some(BlockNumber::GENESIS), BlockNumber::GENESIS, 0, true)]
    #[case::no_attempts(None, BlockNumber::GENESIS, 0, true)]
    #[case::one_attempt(Some(BlockNumber::GENESIS), BlockNumber::from(2), 1, true)]
    #[case::three_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(3), 3, true)]
    #[case::ten_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(13), 10, true)]
    #[case::twenty_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(149), 20, true)]
    #[case::one_attempt_false(Some(BlockNumber::GENESIS), BlockNumber::from(1), 1, false)]
    #[case::three_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(2), 3, false)]
    #[case::ten_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(12), 10, false)]
    #[case::twenty_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(148), 20, false)]
    fn backoff_has_passed(
        #[case] last_attempt_block_num: Option<BlockNumber>,
        #[case] current_block_num: BlockNumber,
        #[case] attempt_count: usize,
        #[case] backoff_should_have_passed: bool,
    ) {
        assert_eq!(
            backoff_should_have_passed,
            has_backoff_passed(current_block_num, last_attempt_block_num, attempt_count)
        );
    }
}
