mod allowlist;
pub mod candidate;
mod execute;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use allowlist::{NoteScriptNotAllowlisted, partition_by_allowlist};
use anyhow::Context;
use candidate::TransactionCandidate;
use futures::FutureExt;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_remote_prover_client::RemoteTransactionProver;
use miden_tx::FailedNote;
use tokio::sync::{Notify, Semaphore, mpsc};

use crate::NoteError;
use crate::chain_state::{ChainState, SharedChainState};
use crate::clients::RpcClient;
use crate::db::Db;

// ACTOR REQUESTS
// ================================================================================================

/// A request sent from an account actor to the coordinator via a shared mpsc channel.
pub enum ActorRequest {
    /// One or more notes failed during transaction execution and should have their attempt counters
    /// incremented. The actor waits for the coordinator to acknowledge the DB write via the oneshot
    /// channel, preventing race conditions where the actor could re-select the same notes before
    /// the failure is persisted.
    NotesFailed {
        failed_notes: Vec<(Nullifier, NoteError)>,
        block_num: BlockNumber,
        ack_tx: tokio::sync::oneshot::Sender<()>,
    },
    /// A note script was fetched from the remote RPC service and should be persisted to the local
    /// DB.
    CacheNoteScript { script_root: Word, script: NoteScript },
}

// ACTOR SUB-STRUCTS
// ================================================================================================

/// gRPC clients used by an account actor to interact with the node's services.
#[derive(Clone)]
pub struct GrpcClients {
    /// Client for interacting with the RPC service in order to load account state.
    pub rpc: RpcClient,
    /// Client for remote transaction proving. If `None`, transactions will be proven locally, which
    /// is undesirable due to the performance impact.
    pub prover: Option<RemoteTransactionProver>,
}

/// Shared state read (and written, in the case of `db`) by all account actors.
#[derive(Clone)]
pub struct State {
    /// Local database for account state, notes, and transaction tracking.
    pub db: Db,
    /// The latest chain state. A single chain state is shared among all actors.
    pub chain: Arc<SharedChainState>,
    /// Shared LRU cache for storing retrieved note scripts to avoid repeated RPC calls.
    pub script_cache: LruCache<Word, NoteScript>,
}

/// Per-actor configuration knobs.
#[derive(Debug, Clone, Copy)]
pub struct ActorConfig {
    /// Maximum number of notes per transaction.
    pub max_notes_per_tx: NonZeroUsize,
    /// Maximum number of note execution attempts before dropping a note.
    pub max_note_attempts: usize,
    /// Duration after which an idle actor will deactivate.
    pub idle_timeout: Duration,
    /// Maximum number of VM execution cycles for network transactions.
    pub max_cycles: u32,
    /// Initial sleep applied between per-request retries on transient infrastructure failures
    /// (prover unreachable, RPC transport error, RPC gRPC hiccup). Doubles each retry up to
    /// [`Self::request_backoff_max`].
    pub request_backoff_initial: Duration,
    /// Upper bound on the per-request retry backoff sleep.
    pub request_backoff_max: Duration,
}

// ACCOUNT ACTOR CONTEXT
// ================================================================================================

/// Contains resources shared by all account actors. The coordinator uses this to spawn new actors.
#[derive(Clone)]
pub struct AccountActorContext {
    pub clients: GrpcClients,
    pub state: State,
    pub config: ActorConfig,
    /// Channel for sending requests to the coordinator (via the builder event loop).
    pub request_tx: mpsc::Sender<ActorRequest>,
}

#[cfg(test)]
impl AccountActorContext {
    /// Creates a minimal `AccountActorContext` suitable for unit tests.
    ///
    /// The URLs are fake and actors spawned with this context will fail on their first gRPC call,
    /// but this is sufficient for testing coordinator logic (registry, deactivation, etc.).
    pub fn test(db: &crate::db::Db) -> Self {
        use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};
        use url::Url;

        use crate::chain_state::SharedChainState;
        use crate::clients::RpcClient;
        use crate::test_utils::mock_block_header;

        let url = Url::parse("http://127.0.0.1:1").unwrap();
        let block_header = mock_block_header(0_u32.into());
        let chain_mmr = PartialMmr::from_peaks(
            MmrPeaks::new(Forest::new(0).expect("forest 0 is valid"), vec![]).unwrap(),
        );
        let chain_state = Arc::new(SharedChainState::new(block_header, chain_mmr));
        let (request_tx, _request_rx) = mpsc::channel(1);

        Self {
            clients: GrpcClients {
                rpc: RpcClient::new(
                    url.clone(),
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                ),
                prover: None,
            },
            state: State {
                db: db.clone(),
                chain: chain_state,
                script_cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
            },
            config: ActorConfig {
                max_notes_per_tx: NonZeroUsize::new(1).unwrap(),
                max_note_attempts: 1,
                idle_timeout: Duration::from_secs(60),
                max_cycles: 1 << 18,
                request_backoff_initial: Duration::from_millis(1),
                request_backoff_max: Duration::from_millis(10),
            },
            request_tx,
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
/// 1. **Initialization**: Waits for committed account state, then checks DB for available notes.
/// 2. **Event Loop**: Continuously processes mempool events and executes transactions.
/// 3. **Transaction Processing**: Selects, executes, proves, and submits transactions through RPC.
/// 4. **State Updates**: Event effects are persisted to DB by the coordinator before actors are
///    notified.
/// 5. **Shutdown**: Terminates gracefully on idle timeout, or returns an error on unrecoverable
///    failures.
///
/// ## Concurrency
///
/// Each actor runs in its own async task and communicates with other system components through
/// shared state. The coordinator signals state changes by notifying a shared [`Notify`]; the
/// actor exits of its own accord when idle for longer than [`ActorConfig::idle_timeout`].
pub struct AccountActor {
    /// The network account this actor is responsible for.
    account_id: AccountId,
    /// gRPC clients used by the actor.
    clients: GrpcClients,
    /// Shared state accessed by the actor.
    state: State,
    /// Per-actor configuration knobs.
    config: ActorConfig,
    /// Notification signal from the coordinator indicating that DB state relevant to this actor may
    /// have changed. The actor re-evaluates its state from the DB on each notification.
    notify: Arc<Notify>,
    /// Channel for sending requests to the coordinator.
    request: mpsc::Sender<ActorRequest>,
}

impl AccountActor {
    /// Constructs a new account actor with the given configuration.
    pub fn new(
        account_id: AccountId,
        actor_context: &AccountActorContext,
        notify: Arc<Notify>,
    ) -> Self {
        Self {
            account_id,
            clients: actor_context.clients.clone(),
            state: actor_context.state.clone(),
            config: actor_context.config,
            notify,
            request: actor_context.request_tx.clone(),
        }
    }

    /// Runs the account actor, processing events and managing state until shutdown.
    ///
    /// The return value signals the shutdown category to the coordinator:
    ///
    /// - `Ok(())`: intentional shutdown (idle timeout or account removal).
    /// - `Err(_)`: crash (database error, semaphore failure, or any other bug).
    pub async fn run(self, semaphore: Arc<Semaphore>) -> anyhow::Result<()> {
        let account_id = self.account_id;

        // Wait for the account to be committed to the DB. For newly created accounts, the creation
        // transaction must be committed before we start processing notes.
        if !self.wait_for_committed_account(account_id).await? {
            return Ok(());
        }

        // Determine initial mode by checking DB for available notes.
        let block_num = self.state.chain.chain_tip_block_number();
        let has_notes = self
            .state
            .db
            .has_available_notes(account_id, block_num, self.config.max_note_attempts)
            .await
            .context("failed to check for available notes")?;

        let mut mode = if has_notes {
            ActorMode::NotesAvailable
        } else {
            ActorMode::NoViableNotes
        };

        loop {
            // Enable or disable transaction execution based on actor mode.
            let tx_permit_acquisition = match mode {
                // Disable transaction execution.
                ActorMode::NoViableNotes | ActorMode::TransactionInflight(_) => {
                    std::future::pending().boxed()
                },
                // Enable transaction execution.
                ActorMode::NotesAvailable => semaphore.acquire().boxed(),
            };

            // Idle timeout timer: only ticks when in NoViableNotes mode. Mode changes cause the
            // next loop iteration to create a fresh sleep or pending.
            let idle_timeout_sleep = match mode {
                ActorMode::NoViableNotes => tokio::time::sleep(self.config.idle_timeout).boxed(),
                _ => std::future::pending().boxed(),
            };

            tokio::select! {
                // Handle coordinator notifications. On notification, re-evaluate state from DB.
                _ = self.notify.notified() => {
                    match mode {
                        ActorMode::TransactionInflight(awaited_id) => {
                            // Check DB: is the inflight tx still pending?
                            let exists = self
                                .state
                                .db
                                .transaction_exists(awaited_id)
                                .await
                                .context("failed to check transaction status")?;
                            if exists {
                                mode = ActorMode::NotesAvailable;
                            }
                        },
                        _ => {
                            mode = ActorMode::NotesAvailable;
                        }
                    }
                },
                // Execute transactions.
                permit = tx_permit_acquisition => {
                    let _permit = permit.context("semaphore closed")?;

                    // Read the chain state.
                    let chain_state = self.state.chain.get_cloned();

                    // Query DB for latest account and available notes.
                    let tx_candidate = self.select_candidate_from_db(
                        account_id,
                        chain_state,
                    ).await?;

                    if let Some(tx_candidate) = tx_candidate {
                        mode = self.execute_transactions(account_id, tx_candidate).await;
                    } else {
                        // No transactions to execute, wait for events.
                        mode = ActorMode::NoViableNotes;
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
        account_id: AccountId,
        chain_state: ChainState,
    ) -> anyhow::Result<Option<TransactionCandidate>> {
        let block_num = chain_state.chain_tip_header.block_num();
        let max_notes = self.config.max_notes_per_tx.get();

        let (latest_account, notes) = self
            .state
            .db
            .select_candidate(account_id, block_num, self.config.max_note_attempts)
            .await
            .context("failed to query DB for transaction candidate")?;

        let Some(account) = latest_account else {
            tracing::info!(account_id = %account_id, "Account no longer exists in DB");
            return Ok(None);
        };

        let partitioned_notes = partition_by_allowlist(&account, notes)
            .context("failed to read network account note allowlist")?;

        if !partitioned_notes.rejected.is_empty() {
            let failed_notes = partitioned_notes
                .rejected
                .into_iter()
                .map(|(nullifier, script_root)| {
                    let error: NoteError = Arc::new(NoteScriptNotAllowlisted::new(script_root));
                    (nullifier, error)
                })
                .collect::<Vec<_>>();
            tracing::info!(
                %account_id,
                rejected_count = failed_notes.len(),
                "dropping network notes whose script roots are not allowlisted",
            );
            self.mark_notes_failed(&failed_notes, block_num).await;
        }

        let notes: Vec<_> = partitioned_notes.allowed.into_iter().take(max_notes).collect();
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

    /// Waits until a committed account state exists in the DB.
    ///
    /// For accounts that are being created by an inflight transaction, this will idle
    /// until the transaction is committed. Returns `true` when the account is ready, or
    /// `false` if no commit arrived within [`ActorConfig::idle_timeout`] — in which case
    /// the coordinator will respawn a new actor when the account reappears through
    /// [`Coordinator::send_targeted`](crate::coordinator::Coordinator::send_targeted) or the
    /// account loader.
    async fn wait_for_committed_account(&self, account_id: AccountId) -> anyhow::Result<bool> {
        // Check if the account is already committed.
        if self
            .state
            .db
            .has_committed_account(account_id)
            .await
            .context("failed to check for committed account")?
        {
            return Ok(true);
        }

        loop {
            tokio::select! {
                _ = self.notify.notified() => {
                    if self
                        .state
                        .db
                        .has_committed_account(account_id)
                        .await
                        .context("failed to check for committed account")?
                    {
                        tracing::info!(account.id=%account_id, "Account committed, starting normal operation");
                        return Ok(true);
                    }
                }
                _ = tokio::time::sleep(self.config.idle_timeout) => {
                    tracing::info!(
                        %account_id,
                        "Account actor deactivated while waiting for account commit",
                    );
                    return Ok(false);
                }
            }
        }
    }

    /// Execute a transaction candidate and mark notes as failed as required.
    ///
    /// Returns the new actor mode based on the execution result.
    ///
    /// Transient infrastructure failures (prover unreachable, RPC transport hiccup, RPC gRPC
    /// error) are retried inside [`execute::NtxContext::execute_transaction`].
    /// Any error reaching this method is therefore terminal for the candidate: the batch's notes
    /// are marked failed and the actor moves on.
    #[tracing::instrument(name = "ntx.actor.execute_transactions", skip(self, tx_candidate))]
    async fn execute_transactions(
        &self,
        account_id: AccountId,
        tx_candidate: TransactionCandidate,
    ) -> ActorMode {
        let block_num = tx_candidate.chain_tip_header.block_num();

        // Execute the selected transaction.
        let context = execute::NtxContext::new(
            self.clients.prover.clone(),
            self.clients.rpc.clone(),
            self.state.script_cache.clone(),
            self.state.db.clone(),
            self.config.max_cycles,
            self.config.request_backoff_initial,
            self.config.request_backoff_max,
        );

        let notes = tx_candidate.notes.clone();
        let account_id = tx_candidate.account.id();
        let note_ids: Vec<_> = notes.iter().map(|n| n.as_note().id()).collect();
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
                ActorMode::TransactionInflight(tx_id)
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

                // For `AllNotesFailed`, use the per-note errors which contain the specific reason
                // each note failed (e.g. consumability check details).
                let failed_notes: Vec<_> = match err {
                    execute::NtxError::AllNotesFailed(per_note) => log_failed_notes(per_note),
                    other => {
                        let error: NoteError = Arc::new(other);
                        notes
                            .iter()
                            .map(|note| {
                                tracing::info!(
                                    note.id = %note.as_note().id(),
                                    nullifier = %note.as_note().nullifier(),
                                    err = %error_msg,
                                    "note failed: transaction execution error",
                                );
                                (note.as_note().nullifier(), error.clone())
                            })
                            .collect()
                    },
                };
                self.mark_notes_failed(&failed_notes, block_num).await;
                ActorMode::NoViableNotes
            },
        }
    }

    /// Sends requests to the coordinator to cache note scripts fetched from the remote RPC service.
    async fn cache_note_scripts(&self, scripts: Vec<(Word, NoteScript)>) {
        for (script_root, script) in scripts {
            if self
                .request
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
            .request
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
            let error_msg = f.error().as_report();
            tracing::info!(
                note.id = %f.note().id(),
                nullifier = %f.note().nullifier(),
                err = %error_msg,
                "note failed: consumability check",
            );
            let error: NoteError = Arc::new(std::io::Error::other(error_msg));
            (f.note().nullifier(), error)
        })
        .collect()
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use tokio::sync::{Notify, mpsc};

    use super::*;

    const OTHER_NOTE_SCRIPT: &str = "\
@note_script
pub proc main
    push.1 drop
end";

    async fn ack_actor_requests(mut rx: mpsc::Receiver<ActorRequest>, db: Db) {
        while let Some(request) = rx.recv().await {
            match request {
                ActorRequest::NotesFailed { failed_notes, block_num, ack_tx } => {
                    db.notes_failed(failed_notes, block_num)
                        .await
                        .expect("test DB write should succeed");
                    let _ = ack_tx.send(());
                },
                ActorRequest::CacheNoteScript { .. } => {},
            }
        }
    }

    fn actor_with_request_handler(
        db: &Db,
        account_id: AccountId,
    ) -> (AccountActor, AccountActorContext) {
        let (request_tx, request_rx) = mpsc::channel(8);
        let mut context = AccountActorContext::test(db);
        context.request_tx = request_tx;
        tokio::spawn(ack_actor_requests(request_rx, db.clone()));

        let actor = AccountActor::new(account_id, &context, Arc::new(Notify::new()));

        (actor, context)
    }

    #[tokio::test]
    #[ignore = "wip refactor"]
    async fn select_candidate_keeps_allowlisted_notes() {
        // let (db, _dir) = Db::test_setup().await;
        // let account_id = mock_network_account_id();
        // let note = mock_single_target_note(account_id, 10);
        // let account = mock_account_with_auth_component(
        //     AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([note
        //         .as_note()
        //         .script()
        //         .root()]))
        //     .expect("non-empty allowlist should construct"),
        // );

        // db.sync_account_from_store(account_id, account, vec![note.clone()])
        //     .await
        //     .expect("fixtures should sync");

        // let (actor, context) = actor_with_request_handler(&db, account_id); let chain_state =
        // context.state.chain.get_cloned();

        // let candidate = actor
        //     .select_candidate_from_db(account_id, chain_state)
        //     .await
        //     .expect("selection should succeed")
        //     .expect("allowed note should produce a candidate");

        // assert_eq!(candidate.notes.len(), 1);
        // assert_eq!(candidate.notes[0].as_note().nullifier(), note.as_note().nullifier());
    }

    #[tokio::test]
    #[ignore = "wip refactor"]
    async fn select_candidate_marks_non_allowlisted_notes_failed() {
        // let (db, _dir) = Db::test_setup().await;
        // let account_id = mock_network_account_id();
        // let allowed_note = mock_single_target_note(account_id, 10);
        // let rejected_note =
        //     mock_single_target_note_with_code(account_id, 20, Some(OTHER_NOTE_SCRIPT));
        // let account = mock_account_with_auth_component(
        //     AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([allowed_note
        //         .as_note()
        //         .script()
        //         .root()]))
        //     .expect("non-empty allowlist should construct"),
        // );

        // db.sync_account_from_store(account_id, account, vec![rejected_note.clone()])
        //     .await
        //     .expect("fixtures should sync");

        // let (actor, context) = actor_with_request_handler(&db, account_id); let chain_state =
        // context.state.chain.get_cloned();

        // let candidate = actor
        //     .select_candidate_from_db(account_id, chain_state)
        //     .await
        //     .expect("selection should succeed");

        // assert!(candidate.is_none());

        // let status = db
        //     .get_note_status(rejected_note.as_note().id())
        //     .await
        //     .expect("status query should succeed")
        //     .expect("note should exist");
        // assert_eq!(status.attempt_count, 1);
        // assert!(
        //     status
        //         .last_error
        //         .as_deref()
        //         .expect("rejected note should record an error")
        //         .contains("not allowlisted")
        // );
    }

    #[tokio::test]
    #[ignore = "wip refactor"]
    async fn select_candidate_executes_allowed_notes_and_marks_rejected_notes_failed() {
        // let (db, _dir) = Db::test_setup().await;
        // let account_id = mock_network_account_id();
        // let allowed_note = mock_single_target_note(account_id, 10);
        // let rejected_note =
        //     mock_single_target_note_with_code(account_id, 20, Some(OTHER_NOTE_SCRIPT));
        // let account = mock_account_with_auth_component(
        //     AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([allowed_note
        //         .as_note()
        //         .script()
        //         .root()]))
        //     .expect("non-empty allowlist should construct"),
        // );

        // db.sync_account_from_store(
        //     account_id,
        //     account,
        //     vec![allowed_note.clone(), rejected_note.clone()],
        // )
        // .await
        // .expect("fixtures should sync");

        // let (actor, context) = actor_with_request_handler(&db, account_id); let chain_state =
        // context.state.chain.get_cloned();

        // let candidate = actor
        //     .select_candidate_from_db(account_id, chain_state)
        //     .await
        //     .expect("selection should succeed")
        //     .expect("allowed note should remain");

        // assert_eq!(candidate.notes.len(), 1);
        // assert_eq!(candidate.notes[0].as_note().nullifier(), allowed_note.as_note().nullifier());

        // let rejected_status = db
        //     .get_note_status(rejected_note.as_note().id())
        //     .await
        //     .expect("status query should succeed")
        //     .expect("rejected note should exist");
        // assert_eq!(rejected_status.attempt_count, 1);
    }
}
