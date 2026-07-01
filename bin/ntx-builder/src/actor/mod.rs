mod allowlist;
pub mod candidate;
mod execute;

use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use allowlist::{NoteScriptNotAllowlisted, partition_by_allowlist};
use anyhow::Context;
use candidate::TransactionCandidate;
use futures::FutureExt;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountDelta, AccountId};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteScript, Nullifier};
use miden_protocol::transaction::{TransactionId, TransactionScript};
use miden_remote_prover_client::RemoteTransactionProver;
use miden_standards::code_builder::CodeBuilder;
use miden_tx::FailedNote;
use tokio::sync::{Notify, Semaphore, mpsc};

use crate::NoteError;
use crate::chain_state::{ChainState, SharedChainState};
use crate::clients::RpcClient;
use crate::db::Db;

/// Compiles the standalone transaction script that sets the on-chain expiration of a network
/// transaction to `delta` blocks. The script is account-independent, so the builder compiles it
/// once at startup and shares the resulting [`TransactionScript`] across all actors.
///
/// ```masm
/// begin
///     push.{delta} exec.::miden::protocol::tx::update_expiration_block_delta
/// end
/// ```
pub(crate) fn expiration_tx_script(delta: NonZeroU16) -> anyhow::Result<TransactionScript> {
    let delta = delta.get();
    let source = format!(
        "begin\n    push.{delta} exec.::miden::protocol::tx::update_expiration_block_delta\nend"
    );
    CodeBuilder::new()
        .compile_tx_script(source)
        .context("failed to compile network-tx expiration script")
}

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
    /// Client for remote transaction proving.
    pub prover: RemoteTransactionProver,
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
    /// Pre-compiled transaction script that sets each network tx's on-chain expiration delta.
    /// Shared into every executed transaction.
    pub expiration_script: TransactionScript,
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
    /// Number of blocks after which a submitted transaction expires. Set as the on-chain expiration
    /// delta and reused as the `WaitForBlock` retry timeout.
    pub tx_expiration_delta: NonZeroU16,
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
    /// Channel for sending requests to the coordinator (via the builder loop).
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
                    miden_protocol::Word::default(),
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                )
                .expect("rpc client should be constructed"),
                prover: RemoteTransactionProver::new(url.as_str()),
            },
            state: State {
                db: db.clone(),
                chain: chain_state,
                script_cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
                expiration_script: expiration_tx_script(NonZeroU16::new(30).unwrap())
                    .expect("expiration script should compile"),
            },
            config: ActorConfig {
                max_notes_per_tx: NonZeroUsize::new(1).unwrap(),
                max_note_attempts: 1,
                idle_timeout: Duration::from_secs(60),
                max_cycles: 1 << 18,
                tx_expiration_delta: NonZeroU16::new(30).unwrap(),
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
    /// No notes targeting this account are currently available. The actor sleeps on the idle
    /// timeout and awaits a coordinator notification to re-evaluate.
    NoViableNotes,
    /// Notes are available for consumption. The actor acquires a transaction permit and submits a
    /// candidate.
    NotesAvailable,
    /// A network transaction has been submitted; the actor waits for it to land in a committed
    /// block. Landing is detected from the local DB: `apply_committed_block` records the
    /// transaction id that updated each network account as `accounts.last_tx_id`, so the actor
    /// checks whether its own submitted id is the account's latest. On landing it applies
    /// `pending_delta` to its in-memory account, avoiding a re-read of the full account from the
    /// database.
    WaitForBlock {
        /// Id of the network transaction the actor submitted.
        submitted_tx_id: TransactionId,
        /// Chain tip block number at submission. With [`ActorConfig::tx_expiration_delta`] this
        /// bounds how long the actor waits before retrying.
        submitted_at: BlockNumber,
        /// The account delta the submitted transaction produced, applied to the in-memory account
        /// once the transaction lands.
        pending_delta: AccountDelta,
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
/// - **Chain Integration**: Reacts to committed-chain updates persisted by the coordinator to stay
///   synchronized with the network state.
///
/// ## Lifecycle
///
/// 1. **Initialization**: Loads the committed account state (guaranteed to exist, since the
///    coordinator only spawns actors for committed accounts), then checks DB for available notes.
/// 2. **Event Loop**: Re-evaluates database state on notification and executes transactions.
/// 3. **Transaction Processing**: Selects, executes, proves, and submits transactions through RPC.
/// 4. **State Updates**: Committed-chain updates are persisted to DB before actors are
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

    /// Runs the account actor, processing notifications and managing state until shutdown.
    ///
    /// The return value signals the shutdown category to the coordinator:
    ///
    /// - `Ok(())`: intentional shutdown (idle timeout).
    /// - `Err(_)`: crash (database error, semaphore failure, or any other bug).
    pub async fn run(self, semaphore: Arc<Semaphore>) -> anyhow::Result<()> {
        let account_id = self.account_id;

        // Load the account once and keep it in memory for the actor's lifetime, advancing it from
        // the delta of each transaction the actor itself lands. The coordinator only spawns actors
        // for accounts whose creation has been committed, so the account must exist.
        let mut account = self
            .state
            .db
            .get_account(account_id)
            .await
            .context("failed to load committed account")?
            .context("no committed state for the account; the coordinator must only spawn actors for committed accounts")?;

        // Determine initial mode by checking the DB for available notes.
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

        // Absolute instant at which the actor deactivates if it has done no real work. The
        // coordinator wakes every actor on every committed block, so a relative timer would restart
        // on each notification and a workless actor would never expire on an active chain. The
        // deadline is only pushed back when the actor actually executes a transaction.
        let mut idle_deadline = tokio::time::Instant::now() + self.config.idle_timeout;

        loop {
            // Acquire an execution permit only when there are notes to process.
            let tx_permit_acquisition = match mode {
                ActorMode::NoViableNotes | ActorMode::WaitForBlock { .. } => {
                    std::future::pending().boxed()
                },
                ActorMode::NotesAvailable => semaphore.acquire().boxed(),
            };

            // The idle timer only ticks while there is nothing to do.
            let idle_timeout_sleep = match mode {
                ActorMode::NoViableNotes => tokio::time::sleep_until(idle_deadline).boxed(),
                _ => std::future::pending().boxed(),
            };

            tokio::select! {
                // A committed block touched this account (or the coordinator woke everyone): the
                // submission may have landed (advancing the in-memory account by its own delta),
                // the submission may have expired, or new notes may be available.
                _ = self.notify.notified() => {
                    mode = self.reevaluate_mode(&mut account, mode).await?;
                },
                // Execute a transaction once a permit is available.
                permit = tx_permit_acquisition => {
                    let _permit = permit.context("semaphore closed")?;
                    let chain_state = self.state.chain.get_cloned();
                    let tx_candidate = self.select_candidate(&account, chain_state).await?;
                    mode = match tx_candidate {
                        Some(candidate) => {
                            let next = self.execute_transactions(account_id, candidate).await;
                            // The actor did real work; push the idle deadline back.
                            idle_deadline = tokio::time::Instant::now() + self.config.idle_timeout;
                            next
                        },
                        None => ActorMode::NoViableNotes,
                    };
                }
                // Idle timeout: actor has been idle too long, deactivate.
                () = idle_timeout_sleep => {
                    tracing::info!(%account_id, "Account actor deactivated due to idle timeout");
                    return Ok(());
                }
            }
        }
    }

    /// Decides the actor's next mode after a coordinator notification, advancing the in-memory
    /// account when the actor's own transaction lands.
    ///
    /// - In `NoViableNotes`/`NotesAvailable`, a wake means the DB may now have new work; advance to
    ///   `NotesAvailable` and let the next `select_candidate` decide whether a real candidate
    ///   exists.
    /// - In `WaitForBlock`, query the latest transaction recorded against the account:
    ///   - If it equals the actor's submitted id, the transaction landed: apply its `pending_delta`
    ///     to the in-memory account and resume selection.
    ///   - Else if `tx_expiration_delta` blocks have passed since submission, the submission expired:
    ///     reload the account from the DB (in case a different transaction changed it while we
    ///     waited) and resume selection.
    ///   - Otherwise keep waiting.
    async fn reevaluate_mode(
        &self,
        account: &mut Account,
        mode: ActorMode,
    ) -> anyhow::Result<ActorMode> {
        let ActorMode::WaitForBlock {
            submitted_tx_id,
            submitted_at,
            pending_delta,
        } = mode
        else {
            return Ok(ActorMode::NotesAvailable);
        };

        let landed = self
            .state
            .db
            .account_last_tx(self.account_id)
            .await
            .context("failed to check submitted tx landing")?
            == Some(submitted_tx_id);
        if landed {
            // The landed transaction is the one we executed, so the committed state is exactly our
            // in-memory account plus the delta it produced.
            account
                .apply_delta(&pending_delta)
                .context("failed to apply landed transaction delta to in-memory account")?;
            tracing::info!(
                account_id = %self.account_id,
                tx_id = %submitted_tx_id,
                "submitted transaction landed; advanced in-memory account by its delta",
            );
            return Ok(ActorMode::NotesAvailable);
        }

        let chain_tip = self.state.chain.chain_tip_block_number();
        let elapsed = chain_tip.checked_sub(submitted_at.as_u32()).unwrap_or_default();
        if elapsed.as_u32() >= u32::from(self.config.tx_expiration_delta.get()) {
            tracing::info!(
                account_id = %self.account_id,
                %submitted_at,
                current_tip = %chain_tip,
                delta = self.config.tx_expiration_delta,
                "submitted transaction expired",
            );
            // The submission did not land. Reload the authoritative account in case a different
            // transaction changed it while we waited, then resume selection.
            if let Some(latest) = self
                .state
                .db
                .get_account(self.account_id)
                .await
                .context("failed to reload account after submission expiry")?
            {
                *account = latest;
            }
            return Ok(ActorMode::NotesAvailable);
        }

        Ok(ActorMode::WaitForBlock {
            submitted_tx_id,
            submitted_at,
            pending_delta,
        })
    }

    /// Selects a transaction candidate for the in-memory account by querying its available notes.
    async fn select_candidate(
        &self,
        account: &Account,
        chain_state: ChainState,
    ) -> anyhow::Result<Option<TransactionCandidate>> {
        let account_id = self.account_id;
        let block_num = chain_state.chain_tip_header.block_num();
        let max_notes = self.config.max_notes_per_tx.get();

        let notes = self
            .state
            .db
            .available_notes(account_id, block_num, self.config.max_note_attempts)
            .await
            .context("failed to query DB for available notes")?;

        let partitioned_notes = partition_by_allowlist(account, notes)
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
            account: account.clone(),
            notes,
            chain_tip_header,
            chain_mmr,
        }))
    }

    /// Execute a transaction candidate and mark notes as failed as required.
    ///
    /// Returns the new actor mode based on the execution result.
    ///
    /// Transient infrastructure failures (prover unreachable, RPC transport hiccup, RPC gRPC
    /// error) are retried inside [`execute::NtxContext::execute_transaction`].
    /// Any error reaching this method is therefore terminal for the candidate: the batch's notes
    /// are marked failed and the actor moves on.
    #[miden_instrument(name = "ntx.actor.execute_transactions", skip(self, tx_candidate))]
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
            self.state.expiration_script.clone(),
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
            Ok(execute::NtxExecutionResult {
                tx_id,
                account_delta,
                failed_notes: failed,
                fetched_scripts,
            }) => {
                tracing::info!(
                    %account_id,
                    %tx_id,
                    num_failed = failed.len(),
                    "network transaction executed with some failed notes",
                );
                self.cache_note_scripts(fetched_scripts).await;

                // A tx carries work only if at least one candidate note survived consumability
                // filtering; if every note failed there is nothing on-chain to wait for.
                let all_notes_failed = failed.len() == notes.len();

                if !failed.is_empty() {
                    let failed_notes = log_failed_notes(failed);
                    self.mark_notes_failed(&failed_notes, block_num).await;
                }

                if all_notes_failed {
                    ActorMode::NoViableNotes
                } else {
                    ActorMode::WaitForBlock {
                        submitted_tx_id: tx_id,
                        submitted_at: block_num,
                        pending_delta: account_delta,
                    }
                }
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
    use std::num::NonZeroU16;

    use miden_protocol::ONE;
    use miden_protocol::account::{Account, AccountDelta, AccountStorageDelta, AccountVaultDelta};
    use tokio::sync::Notify;

    use super::*;
    use crate::db::Db;
    use crate::test_utils::{mock_account, mock_network_account_id, mock_transaction_id};

    /// Builds a valid nonce-only [`AccountDelta`] for `account_id`.
    fn nonce_bump_delta(account_id: AccountId) -> AccountDelta {
        AccountDelta::new(
            account_id,
            AccountStorageDelta::default(),
            AccountVaultDelta::default(),
            ONE,
        )
        .expect("a nonce-only delta is valid")
    }

    /// Builds an actor wired to `db` for the given account, plus the in-memory account to drive.
    fn test_actor(db: &Db, account: &Account) -> AccountActor {
        let ctx = AccountActorContext::test(db);
        AccountActor::new(account.id(), &ctx, Arc::new(Notify::new()))
    }

    /// When the submitted transaction lands (its id is the account's latest committed tx), the
    /// actor advances its in-memory account by exactly the delta the transaction produced.
    #[tokio::test]
    async fn landing_advances_in_memory_account_by_its_delta() {
        let (db, _dir) = Db::test_setup().await;
        let account = mock_account(mock_network_account_id());
        let account_id = account.id();
        let submitted = mock_transaction_id(7);

        // Seed the committed row so the landing check sees our submission as the latest tx.
        db.upsert_account_for_test(account_id, account.clone(), submitted)
            .await
            .unwrap();

        let delta = nonce_bump_delta(account_id);
        let mut expected = account.clone();
        expected.apply_delta(&delta).unwrap();

        let actor = test_actor(&db, &account);
        let mut in_memory = account.clone();
        let mode = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::WaitForBlock {
                    submitted_tx_id: submitted,
                    submitted_at: 0_u32.into(),
                    pending_delta: delta,
                },
            )
            .await
            .unwrap();

        assert!(matches!(mode, ActorMode::NotesAvailable), "a landed tx must resume selection");
        assert_eq!(
            in_memory.to_commitment(),
            expected.to_commitment(),
            "the in-memory account must be advanced by the landed tx's delta",
        );
    }

    /// While the submission has neither landed nor expired, the actor keeps waiting and leaves its
    /// in-memory account untouched.
    #[tokio::test]
    async fn pending_submission_keeps_waiting_without_touching_account() {
        let (db, _dir) = Db::test_setup().await;
        let account = mock_account(mock_network_account_id());

        // Nothing seeded: `account_last_tx` returns `None`, so the submission has not landed. The
        // test chain sits at genesis, well within `tx_expiration_delta`, so it has not expired.
        let actor = test_actor(&db, &account);
        let mut in_memory = account.clone();
        let submitted = mock_transaction_id(7);
        let mode = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::WaitForBlock {
                    submitted_tx_id: submitted,
                    submitted_at: 0_u32.into(),
                    pending_delta: nonce_bump_delta(account.id()),
                },
            )
            .await
            .unwrap();

        match mode {
            ActorMode::WaitForBlock { submitted_tx_id, .. } => {
                assert_eq!(submitted_tx_id, submitted, "the actor must keep waiting on its own tx");
            },
            other => panic!("expected to stay in WaitForBlock, got {other:?}"),
        }
        assert_eq!(
            in_memory.to_commitment(),
            account.to_commitment(),
            "a still-pending submission must not change the in-memory account",
        );
    }

    /// The idle timeout must still fire while the coordinator keeps waking the actor every block.
    /// The coordinator notifies every registered actor on every committed block, so a workless
    /// actor would never expire if notifications reset the idle timer. The deadline is absolute and
    /// only pushed back by real work, so repeated notifications cannot keep a no-work actor
    /// resident indefinitely.
    #[tokio::test]
    async fn idle_timeout_fires_despite_repeated_notifications() {
        let (db, _dir) = Db::test_setup().await;
        // A real network account with a populated allowlist, so re-evaluation on each wake reaches
        // a clean "no viable notes" outcome instead of erroring on a missing allowlist slot.
        let (account, _) = crate::test_utils::mock_network_account_update();
        let account_id = account.id();

        // Seed the committed account but no notes, so the actor starts and stays in NoViableNotes:
        // every wake re-checks the DB, finds nothing, and returns to the idle state.
        db.upsert_account_for_test(account_id, account.clone(), mock_transaction_id(1))
            .await
            .unwrap();

        let mut ctx = AccountActorContext::test(&db);
        // Short idle timeout keeps the test fast.
        ctx.config.idle_timeout = Duration::from_millis(300);

        let notify = Arc::new(Notify::new());
        let actor = AccountActor::new(account_id, &ctx, notify.clone());
        let semaphore = Arc::new(Semaphore::new(1));
        let handle = tokio::spawn(actor.run(semaphore));

        // Wake the actor far more often than the idle timeout, and keep doing so for longer than
        // the test's deadline. With a per-iteration `sleep(idle_timeout)` every wake would restart
        // the timer and the actor would never deactivate, failing the timeout below.
        let notifier = tokio::spawn(async move {
            loop {
                notify.notify_one();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("actor must deactivate on idle timeout despite repeated notifications")
            .expect("actor task should not panic");
        assert!(result.is_ok(), "idle deactivation is a clean shutdown");

        notifier.abort();
    }

    /// The expiration script must compile for the full valid delta range, and the delta must be
    /// baked into the script (distinct deltas → distinct script roots), proving the on-chain
    /// expiration value is actually carried rather than ignored.
    #[test]
    fn expiration_script_compiles_and_encodes_delta() {
        let one =
            expiration_tx_script(NonZeroU16::new(1).unwrap()).expect("delta 1 should compile");
        let thirty =
            expiration_tx_script(NonZeroU16::new(30).unwrap()).expect("delta 30 should compile");
        let max = expiration_tx_script(NonZeroU16::MAX).expect("delta u16::MAX should compile");

        assert_ne!(one.root(), thirty.root(), "distinct deltas must yield distinct scripts");
        assert_ne!(thirty.root(), max.root(), "distinct deltas must yield distinct scripts");
    }
}
