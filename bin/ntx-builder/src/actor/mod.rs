pub mod candidate;
mod execute;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use candidate::TransactionCandidate;
pub use execute::compile_expiration_tx_script;
use futures::FutureExt;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteScript, Nullifier};
use miden_protocol::transaction::TransactionScript;
use miden_remote_prover_client::RemoteTransactionProver;
use miden_tx::FailedNote;
use tokio::sync::{Notify, Semaphore, mpsc};

use crate::NoteError;
use crate::chain_state::{ChainState, SharedChainState};
use crate::clients::{BlockProducerClient, StoreClient, ValidatorClient};
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
    /// A note script was fetched from the remote store and should be persisted to the local DB.
    CacheNoteScript { script_root: Word, script: NoteScript },
}

// ACTOR SUB-STRUCTS
// ================================================================================================

/// gRPC clients used by an account actor to interact with the node's services.
#[derive(Clone)]
pub struct GrpcClients {
    /// Client for interacting with the store in order to load account state.
    pub store: StoreClient,
    /// Client for interacting with the block producer.
    pub block_producer: BlockProducerClient,
    /// Client for interacting with the validator.
    pub validator: ValidatorClient,
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
    /// Shared LRU cache for storing retrieved note scripts to avoid repeated store calls.
    pub script_cache: LruCache<Word, NoteScript>,
}

/// Per-actor configuration knobs.
#[derive(Debug, Clone)]
pub struct ActorConfig {
    /// Maximum number of notes per transaction.
    pub max_notes_per_tx: NonZeroUsize,
    /// Maximum number of note execution attempts before dropping a note.
    pub max_note_attempts: usize,
    /// Duration after which an idle actor will deactivate.
    pub idle_timeout: Duration,
    /// Maximum number of VM execution cycles for network transactions.
    pub max_cycles: u32,
    /// Pre-compiled tx script that sets each submitted transaction's expiration block delta.
    /// Built once at builder startup and shared by all actors.
    pub expiration_script: TransactionScript,
    /// Same delta encoded in [`Self::expiration_script`], retained so the actor can decide when a
    /// submitted transaction must have either landed or been dropped.
    pub tx_expiration_delta: u16,
    /// Initial sleep applied between per-request retries on transient infrastructure failures
    /// (prover unreachable, validator/block-producer transport error, store gRPC hiccup). Doubles
    /// each retry up to [`Self::request_backoff_max`].
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
        use crate::clients::StoreClient;
        use crate::test_utils::mock_block_header;

        let url = Url::parse("http://127.0.0.1:1").unwrap();
        let block_header = mock_block_header(0_u32.into());
        let chain_mmr = PartialMmr::from_peaks(MmrPeaks::new(Forest::new(0), vec![]).unwrap());
        let chain_state = Arc::new(SharedChainState::new(block_header, chain_mmr));
        let (request_tx, _request_rx) = mpsc::channel(1);

        Self {
            clients: GrpcClients {
                store: StoreClient::new(url.clone()),
                block_producer: BlockProducerClient::new(url.clone()),
                validator: ValidatorClient::new(url),
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
                expiration_script: crate::actor::compile_expiration_tx_script(5),
                tx_expiration_delta: 5,
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
    /// The actor has just submitted a transaction and is waiting for it to either land on-chain or
    /// expire before doing any more work for this account. This avoids busy-looping with the same
    /// notes between submit and block commit.
    ///
    /// Carries the commitment of the account state we executed against and the chain tip at
    /// submission time, so on each wake-up we can detect cheaply whether the tx landed (the
    /// committed account commitment in the DB has moved) or definitely won't (the chain has
    /// advanced past the expiration window).
    ///
    /// Network accounts are only ever updated by ntx-builder transactions, so a commitment change
    /// here is equivalent to "some submission for this account has been included in a block."
    WaitForNextBlock {
        submitted_commitment: Word,
        submitted_at: BlockNumber,
    },
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
/// 3. **Transaction Processing**: Selects, executes, and proves transactions, and submits them to
///    block producer.
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
    account_id: NetworkAccountId,
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
        account_id: NetworkAccountId,
        actor_context: &AccountActorContext,
        notify: Arc<Notify>,
    ) -> Self {
        Self {
            account_id,
            clients: actor_context.clients.clone(),
            state: actor_context.state.clone(),
            config: actor_context.config.clone(),
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
                ActorMode::NoViableNotes | ActorMode::WaitForNextBlock { .. } => {
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
                // Handle coordinator notifications. Whether we re-evaluate depends on whether
                // an in-flight submission still might land.
                _ = self.notify.notified() => {
                    mode = self.on_notified(mode).await?;
                },
                // Execute transactions.
                permit = tx_permit_acquisition => {
                    let _permit = permit.context("semaphore closed")?;

                    // Read the chain state and query the DB for an executable candidate.
                    let chain_state = self.state.chain.get_cloned();
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

    /// Decides the next mode when a coordinator notification arrives.
    ///
    /// If we are in [`ActorMode::WaitForNextBlock`], we only transition out once either:
    /// - the committed account commitment in the DB no longer matches the one we executed against,
    ///   which means some network transaction for this account has been included in a block, or
    /// - the chain has advanced past the expiration window, in which case the submission must be
    ///   considered dropped.
    ///
    /// While neither holds we stay in `WaitForNextBlock` so the actor does not re-execute and
    /// re-submit the same notes every block. In any other mode we move to
    /// [`ActorMode::NotesAvailable`] so the next loop iteration re-queries the DB.
    async fn on_notified(&self, mode: ActorMode) -> anyhow::Result<ActorMode> {
        let ActorMode::WaitForNextBlock { submitted_commitment, submitted_at } = mode else {
            return Ok(ActorMode::NotesAvailable);
        };

        let chain_tip = self.state.chain.chain_tip_block_number();
        let blocks_elapsed = chain_tip.as_u32().saturating_sub(submitted_at.as_u32());
        let expired = blocks_elapsed >= u32::from(self.config.tx_expiration_delta);

        if expired {
            // Submission can no longer be included; re-evaluate from scratch.
            return Ok(ActorMode::NotesAvailable);
        }

        let current = self
            .state
            .db
            .account_commitment(self.account_id)
            .await
            .context("failed to read account commitment")?;

        // The account row goes away only if the network account was removed entirely. Treat that
        // as "something changed" so the next iteration re-evaluates (and almost certainly idles).
        if current == Some(submitted_commitment) {
            Ok(ActorMode::WaitForNextBlock { submitted_commitment, submitted_at })
        } else {
            Ok(ActorMode::NotesAvailable)
        }
    }

    /// Selects a transaction candidate by querying the DB.
    async fn select_candidate_from_db(
        &self,
        account_id: NetworkAccountId,
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

    /// Waits until a committed account state exists in the DB.
    ///
    /// For accounts that are being created by an inflight transaction, this will idle
    /// until the transaction is committed. Returns `true` when the account is ready, or
    /// `false` if no commit arrived within [`ActorConfig::idle_timeout`] — in which case
    /// the coordinator will respawn a new actor when the account reappears through
    /// [`Coordinator::send_targeted`](crate::coordinator::Coordinator::send_targeted) or the
    /// account loader.
    async fn wait_for_committed_account(
        &self,
        account_id: NetworkAccountId,
    ) -> anyhow::Result<bool> {
        // Check if the account is already committed.
        if self
            .state
            .db
            .has_account(account_id)
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
                        .has_account(account_id)
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
    /// Transient infrastructure failures (prover unreachable, validator/block-producer transport
    /// hiccup, store gRPC error) are retried inside [`execute::NtxContext::execute_transaction`].
    /// Any error reaching this method is therefore terminal for the candidate: the batch's notes
    /// are marked failed and the actor moves on.
    #[tracing::instrument(name = "ntx.actor.execute_transactions", skip(self, tx_candidate))]
    async fn execute_transactions(
        &self,
        account_id: NetworkAccountId,
        tx_candidate: TransactionCandidate,
    ) -> ActorMode {
        // Captured before execution so that `WaitForNextBlock` records the state the tx was run
        // against even though `tx_candidate` is moved into the executor below.
        let submitted_commitment = tx_candidate.account.to_commitment();
        let submitted_at = tx_candidate.chain_tip_header.block_num();
        let block_num = submitted_at;

        // Execute the selected transaction.
        let context = execute::NtxContext::new(
            self.clients.block_producer.clone(),
            self.clients.validator.clone(),
            self.clients.prover.clone(),
            self.clients.store.clone(),
            self.state.script_cache.clone(),
            self.state.db.clone(),
            self.config.max_cycles,
            self.config.expiration_script.clone(),
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
                ActorMode::WaitForNextBlock { submitted_commitment, submitted_at }
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

    /// Sends requests to the coordinator to cache note scripts fetched from the remote store.
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
