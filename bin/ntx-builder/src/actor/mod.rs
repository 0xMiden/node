mod allowlist;
pub mod candidate;
mod execute;

use std::collections::{HashMap, HashSet};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use allowlist::{NoteScriptNotAllowlisted, partition_by_allowlist};
use anyhow::Context;
use candidate::{SponsoredFeatureNote, TransactionCandidate};
use futures::FutureExt;
use miden_node_tracing::{ErrorReport, debug, error, info, miden_instrument, warn};
use miden_node_utils::formatting::format_opt;
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId, AccountPatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::{TransactionArgs, TransactionId};
use miden_standards::account::fees::FeePolicyManager;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_tx::FailedNote;
use tokio::sync::{Semaphore, mpsc, watch};

use crate::chain_state::{ChainState, SharedChainState};
use crate::clients::{RemoteTransactionProver, RpcClient};
use crate::coordinator::AccountView;
use crate::db::NtxDbReader;
use crate::{LOG_TARGET, NoteError};

/// Builds the [`TransactionArgs`] shared by every network transaction.
///
/// Currently these attach the canonical [`ExpirationTransactionScript`] for `expiration_delta`
/// blocks, with the script paired to the `TX_SCRIPT_ARGS` word it reads its delta from.
///
/// The script itself is account-independent and its MAST root is identical for every delta (the
/// delta travels in the args word, not the code), so the builder derives these once at startup and
/// shares them across all actors. The matching root
/// ([`ExpirationTransactionScript::script_root`]) is what network accounts must allowlist for these
/// transactions to be accepted on-chain.
pub(crate) fn build_tx_args(expiration_delta: NonZeroU16) -> TransactionArgs {
    let script = ExpirationTransactionScript::new(expiration_delta);
    TransactionArgs::default().with_tx_script_and_args(script.into(), script.tx_script_args())
}

/// Maximum number of `FEE_SPONSORSHIP` notes attached to a single feature note. A feature note with
/// more pending sponsorships than this keeps a subset of this size.
const MAX_SPONSORSHIPS_PER_NOTE: usize = 3;

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
    /// One or more notes were proven to exceed the per-tx cycle budget on their own and can never
    /// be consumed. They should be marked permanently unconsumable (discarded) so they are not
    /// re-selected. The actor waits for the DB write to be acknowledged before re-selecting notes.
    NotesDiscarded {
        nullifiers: Vec<Nullifier>,
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
    pub db: NtxDbReader,
    /// The latest chain state. A single chain state is shared among all actors.
    pub chain: Arc<SharedChainState>,
    /// Shared LRU cache for storing retrieved note scripts to avoid repeated RPC calls.
    pub script_cache: LruCache<Word, NoteScript>,
    /// [`TransactionArgs`] used by every network transaction.
    ///
    /// These are constant and are therefore prebuilt and cloned for each transaction.
    ///
    /// Currently this contains the transaction expiration script.
    pub tx_args: TransactionArgs,
}

/// Per-actor configuration knobs.
#[derive(Debug, Clone, Copy)]
pub struct ActorConfig {
    /// Maximum number of notes per transaction. Sponsorship notes count against this budget.
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
    pub fn test(db: &NtxDbReader) -> Self {
        use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};
        use url::Url;

        use crate::chain_state::SharedChainState;
        use crate::clients::RpcClient;
        use crate::test_utils::mock_block_header;

        let url = Url::parse("http://127.0.0.1:1").unwrap();
        let block_header = mock_block_header(0_u32.into());
        let trusted_validator_signing_keys = block_header.validator_config().keys().to_vec();
        let chain_mmr = PartialMmr::from_peaks(
            MmrPeaks::new(Forest::new(0).expect("forest 0 is valid"), vec![]).unwrap(),
        );
        let chain_state = Arc::new(SharedChainState::new(
            block_header,
            chain_mmr,
            miden_protocol::protocol_config::ProtocolConfig::mock(),
        ));
        let (request_tx, _request_rx) = mpsc::channel(1);
        let tx_args = build_tx_args(NonZeroU16::new(30).unwrap());

        Self {
            clients: GrpcClients {
                rpc: RpcClient::new(
                    url.clone(),
                    miden_protocol::Word::default(),
                    trusted_validator_signing_keys,
                    Duration::from_secs(10),
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                )
                .expect("rpc client should be constructed"),
                prover: RemoteTransactionProver::new(url.clone(), Duration::from_secs(10))
                    .expect("prover client should be constructed"),
            },
            state: State {
                db: db.clone(),
                chain: chain_state,
                script_cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
                tx_args,
            },
            config: ActorConfig {
                max_notes_per_tx: NonZeroUsize::new(1).unwrap(),
                max_note_attempts: 1,
                idle_timeout: Duration::from_mins(1),
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
    /// block. Landing is detected from the pushed [`AccountView`]: the coordinator reports the
    /// latest transaction id committed against each network account (mirroring
    /// `accounts.last_tx_id`), so the actor checks whether its own submitted id is the account's
    /// latest. On landing it applies `pending_patch` to its in-memory account, avoiding a re-read
    /// of the full account from the database.
    WaitForBlock {
        /// Id of the network transaction the actor submitted.
        submitted_tx_id: TransactionId,
        /// Chain tip block number at submission. With [`ActorConfig::tx_expiration_delta`] this
        /// bounds how long the actor waits before retrying.
        submitted_at: BlockNumber,
        /// The account patch the submitted transaction produced, applied to the in-memory account
        /// once the transaction lands.
        pending_patch: AccountPatch,
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
/// - **State Management**: Tracks the account's committed state in memory, advancing it from the
///   [`AccountView`] the coordinator pushes after each block.
/// - **Transaction Selection**: Selects viable notes and constructs a [`TransactionCandidate`]
///   based on current chain state and a DB query for the account's available notes.
/// - **Transaction Execution**: Executes selected transactions using either local or remote
///   proving.
/// - **Chain Integration**: Reacts to per-account [`AccountView`] updates pushed by the coordinator
///   to stay synchronized with the network state.
///
/// ## Lifecycle
///
/// 1. **Initialization**: Loads the committed account state (guaranteed to exist, since the
///    coordinator only spawns actors for committed accounts), then checks DB for available notes.
/// 2. **Event Loop**: Re-evaluates state from the pushed [`AccountView`] and executes transactions.
/// 3. **Transaction Processing**: Selects, executes, proves, and submits transactions through RPC.
/// 4. **State Updates**: Committed-chain updates are persisted to DB and reflected in the view
///    before actors observe them.
/// 5. **Shutdown**: Terminates gracefully on idle timeout (only when it has no pending notes), or
///    returns an error on unrecoverable failures.
///
/// ## Concurrency
///
/// Each actor runs in its own async task and communicates with other system components through
/// shared state. The coordinator signals state changes by pushing an [`AccountView`] over a watch
/// channel; the actor exits of its own accord when idle for longer than
/// [`ActorConfig::idle_timeout`].
pub struct AccountActor {
    /// The network account this actor is responsible for.
    account_id: AccountId,
    /// gRPC clients used by the actor.
    clients: GrpcClients,
    /// Shared state accessed by the actor.
    state: State,
    /// Per-actor configuration knobs.
    config: ActorConfig,
    /// Channel for sending requests to the coordinator.
    request: mpsc::Sender<ActorRequest>,
}

impl AccountActor {
    /// Constructs a new account actor with the given configuration.
    pub fn new(account_id: AccountId, actor_context: &AccountActorContext) -> Self {
        Self {
            account_id,
            clients: actor_context.clients.clone(),
            state: actor_context.state.clone(),
            config: actor_context.config,
            request: actor_context.request_tx.clone(),
        }
    }

    /// Runs the account actor, processing notifications and managing state until shutdown.
    ///
    /// The return value signals the shutdown category to the coordinator:
    ///
    /// - `Ok(())`: intentional shutdown (idle timeout).
    /// - `Err(_)`: crash (database error, semaphore failure, or any other bug).
    pub async fn run(
        self,
        semaphore: Arc<Semaphore>,
        mut view_rx: watch::Receiver<AccountView>,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let account_id = self.account_id;

        // Load the account once and keep it in memory for the actor's lifetime, advancing it from
        // the delta of each transaction the actor itself lands. The coordinator only spawns actors
        // for accounts whose creation has been committed, so the account must exist. Held in an
        // `Arc` so building a transaction candidate shares this account rather than deep-cloning it
        // (expensive for large storage maps). The actor is the sole writer and advances it via
        // `Arc::make_mut`, which is cheap because the account is never mutated while a candidate is
        // in flight (execution is awaited to completion before any patch/reload).
        let mut account = Arc::new(
            self.state
                .db
                .get_account(account_id)
                .await
                .context("failed to load committed account")?
                .context("no committed state for the account; the coordinator must only spawn actors for committed accounts")?,
        );

        // Determine initial mode by querying the DB for available notes. `next_retry_block` records
        // when a currently-ineligible note (awaiting backoff or an execution-hint window) becomes
        // eligible, so the actor can wait for that block instead of re-querying every block.
        let block_num = self.state.chain.chain_tip_block_number();
        let availability = self
            .state
            .db
            .available_notes(account_id, block_num, self.config.max_note_attempts)
            .await
            .context("failed to check for available notes")?;
        let mut next_retry_block = availability.next_retry_block;
        let mut mode = if availability.eligible.is_empty() {
            ActorMode::NoViableNotes
        } else {
            ActorMode::NotesAvailable
        };

        // Local cursor over the view's monotone note counter. Mark the spawn-time view as seen so
        // the first `changed()` corresponds to the next committed block.
        let mut notes_cursor = view_rx.borrow_and_update().notes_seen;

        // Absolute instant at which the actor deactivates if it has done no real work. The
        // coordinator pushes a view to every actor on every committed block, so a relative timer
        // would restart on each update and a workless actor would never expire on an active chain.
        // The deadline is only pushed back when the actor actually executes a transaction.
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
                ActorMode::NoViableNotes if next_retry_block.is_none() => {
                    tokio::time::sleep_until(idle_deadline).boxed()
                },
                _ => std::future::pending().boxed(),
            };

            tokio::select! {
                // Check shutdown first, then poll the view before the idle timer, so cancellation
                // wins and a pending update is always processed rather than racing an idle
                // shutdown. Tokio native.
                biased;

                () = shutdown.cancelled() => return Ok(()),
                // A committed block updated this account's view: the submission may have landed
                // (advancing the in-memory account by its own delta) or expired, or new notes / a
                // due retry may make work available. All of this is answered in memory.
                changed = view_rx.changed() => {
                    changed.context("coordinator dropped the account view channel")?;
                    let view = view_rx.borrow_and_update().clone();
                    mode = self
                        .reevaluate_mode(&mut account, mode, &view, &mut notes_cursor, next_retry_block)
                        .await?;
                },
                // Execute a transaction once a permit is available.
                permit = tx_permit_acquisition => {
                    let _permit = permit.context("semaphore closed")?;
                    let chain_state = self.state.chain.get_cloned();
                    let (tx_candidate, retry) = self.select_candidate(&account, chain_state).await?;
                    next_retry_block = retry;
                    mode = match tx_candidate {
                        Some(candidate) => {
                            let next = self
                                .execute_transactions(account_id, candidate, &mut account)
                                .await?;
                            // The actor did real work; push the idle deadline back.
                            idle_deadline = tokio::time::Instant::now() + self.config.idle_timeout;
                            next
                        },
                        None => ActorMode::NoViableNotes,
                    };
                }
                // Idle timeout: actor has been idle too long, deactivate.
                () = idle_timeout_sleep => {
                    debug!(
                        target: LOG_TARGET,
                        "Account actor deactivated due to idle timeout",
                        account.id = account_id
                    );
                    return Ok(());
                }
            }
        }
    }

    /// Decides the actor's next mode after the coordinator pushes a fresh [`AccountView`], advancing
    /// the in-memory account when the actor's own transaction lands.
    ///
    /// - In `NotesAvailable`, keep the mode so the pending permit acquisition can complete.
    /// - In `NoViableNotes`, advance to `NotesAvailable` only if the view shows new notes (its
    ///   counter moved past `notes_cursor`) or a scheduled retry is due (`next_retry_block` reached);
    ///   otherwise stay idle without touching the DB.
    /// - In `WaitForBlock`, use the view rather than a DB query:
    ///   - If `last_committed_tx` equals the actor's submitted id, the transaction landed: apply its
    ///     `pending_patch` to the in-memory account and resume selection.
    ///   - Else if `tx_expiration_delta` blocks have passed since submission, the submission expired:
    ///     reload the account from the DB (in case a different transaction changed it while we
    ///     waited) and resume selection.
    ///   - Otherwise keep waiting.
    async fn reevaluate_mode(
        &self,
        account: &mut Arc<Account>,
        mode: ActorMode,
        view: &AccountView,
        notes_cursor: &mut u64,
        next_retry_block: Option<BlockNumber>,
    ) -> anyhow::Result<ActorMode> {
        let next = match mode {
            // A permit acquisition is already in flight; let it complete rather than cancel it.
            ActorMode::NotesAvailable => ActorMode::NotesAvailable,

            // Resume selection only when there is a reason to: new notes arrived, or a previously
            // ineligible note's backoff/hint window is now due. Otherwise stay idle, no DB query.
            ActorMode::NoViableNotes => {
                let new_work = view.notes_seen > *notes_cursor;
                let retry_due = next_retry_block.is_some_and(|block| view.chain_tip >= block);
                if new_work || retry_due {
                    ActorMode::NotesAvailable
                } else {
                    ActorMode::NoViableNotes
                }
            },

            // Waiting on a submission: detect landing or expiry from the view, not the DB.
            ActorMode::WaitForBlock {
                submitted_tx_id,
                submitted_at,
                pending_patch,
            } => {
                let elapsed = view.chain_tip.checked_sub(submitted_at.as_u32()).unwrap_or_default();
                if view.last_committed_tx == Some(submitted_tx_id) {
                    // The landed transaction is the one we executed, so the committed state is our
                    // in-memory account plus the patch it produced. `make_mut` does not clone here:
                    // the candidate that shared this `Arc` was dropped when its execution
                    // completed, so the actor holds the only reference.
                    Arc::make_mut(account)
                        .apply_patch(&pending_patch)
                        .context("failed to apply landed transaction patch to in-memory account")?;
                    info!(
                        target: LOG_TARGET,
                        "submitted transaction landed; advanced in-memory account by its patch",
                        account.id = self.account_id,
                        transaction.id = submitted_tx_id
                    );
                    ActorMode::NotesAvailable
                } else if elapsed.as_u32() >= u32::from(self.config.tx_expiration_delta.get()) {
                    info!(
                        target: LOG_TARGET,
                        "submitted transaction expired",
                        account.id = self.account_id,
                        transaction.submitted_at = submitted_at,
                        tip.number = view.chain_tip,
                        transaction.expiration_delta = self.config.tx_expiration_delta.get()
                    );
                    // The submission did not land. Reload the authoritative account in case a
                    // different transaction changed it while we waited, then resume selection.
                    if let Some(latest) = self
                        .state
                        .db
                        .get_account(self.account_id)
                        .await
                        .context("failed to reload account after submission expiry")?
                    {
                        *account = Arc::new(latest);
                    }
                    ActorMode::NotesAvailable
                } else {
                    ActorMode::WaitForBlock {
                        submitted_tx_id,
                        submitted_at,
                        pending_patch,
                    }
                }
            },
        };

        // Whenever the actor resumes selection it accounts for every note seen so far, so sync the
        // cursor to the view's counter in that one place.
        if matches!(next, ActorMode::NotesAvailable) {
            *notes_cursor = view.notes_seen;
        }
        Ok(next)
    }

    /// Selects a transaction candidate for the in-memory account by querying its available notes.
    ///
    /// Returns the candidate (if any) alongside the earliest block at which a currently-ineligible
    /// note becomes eligible, so the caller can schedule a single re-check instead of polling every
    /// block. `None` for that block means the account has no pending notes awaiting a window.
    async fn select_candidate(
        &self,
        account: &Arc<Account>,
        chain_state: ChainState,
    ) -> anyhow::Result<(Option<TransactionCandidate>, Option<BlockNumber>)> {
        let account_id = self.account_id;
        let block_num = chain_state.chain_tip_header.block_num();
        let max_notes = self.config.max_notes_per_tx.get();

        let max_note_attempts = self.config.max_note_attempts;
        let availability = self
            .state
            .db
            .available_notes(account_id, block_num, max_note_attempts)
            .await
            .context("failed to query DB for available notes")?;
        let next_retry_block = availability.next_retry_block;

        let partitioned_notes = partition_by_allowlist(account.as_ref(), availability.eligible)
            .context("failed to read network account note allowlist")?;

        let rejected_any = !partitioned_notes.rejected.is_empty();
        if rejected_any {
            let failed_notes = partitioned_notes
                .rejected
                .into_iter()
                .map(|(nullifier, script_root)| {
                    let error: NoteError = Arc::new(NoteScriptNotAllowlisted::new(script_root));
                    (nullifier, error)
                })
                .collect::<Vec<_>>();
            info!(
                target: LOG_TARGET,
                "dropping network notes whose script roots are not allowlisted",
                account.id = account_id,
                note.rejected.count = failed_notes.len()
            );
            self.mark_notes_failed(&failed_notes, block_num).await;
        }

        // Attach each feature note's pending sponsorships: the bundle is the atomic selection unit,
        // since a sponsorship may only be consumed alongside its feature note.
        let mut sponsorships = if partitioned_notes.allowed.is_empty() {
            HashMap::new()
        } else {
            self.state
                .db
                .sponsorships_for_pending_notes(account_id)
                .await
                .context("failed to query DB for pending sponsorships")?
        };
        // A bundle must leave room for its feature note within the per-tx note budget.
        let max_sponsorships = MAX_SPONSORSHIPS_PER_NOTE.min(max_notes - 1);
        let fee_asset_id = account
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .context("failed to read network account fee asset ID")?;

        let mut selected: Vec<SponsoredFeatureNote> = Vec::new();
        let mut selected_notes = 0_usize;
        for feature in partitioned_notes.allowed {
            let bundled_sponsorships =
                sponsorships.remove(&feature.as_note().id()).unwrap_or_default();
            let mut sponsored = SponsoredFeatureNote {
                feature,
                sponsorships: bundled_sponsorships,
            };
            // Filter before applying the cap so assets the account does not accept cannot occupy
            // the limited sponsorship slots, then order by amount so the cap keeps the sponsorships
            // most likely to cover the fee.
            sponsored.retain_sponsorships_for_fee_asset(fee_asset_id);
            sponsored.sort_sponsorships_by_amount();
            sponsored.sponsorships.truncate(max_sponsorships);
            // Bundle-atomic packing: a bundle that does not fit the remaining budget is skipped as
            // a whole (never split) and re-selected in a later round.
            if selected_notes + sponsored.num_notes() > max_notes {
                continue;
            }
            selected_notes += sponsored.num_notes();
            selected.push(sponsored);
        }
        if selected.is_empty() {
            // Notes just marked failed re-enter eligibility via backoff; re-check on the next block
            // so the actor does not deactivate while it still has notes aging through their budget.
            let next_retry_block = if rejected_any {
                Some(
                    next_retry_block
                        .map_or(block_num.child(), |block| block.min(block_num.child())),
                )
            } else {
                next_retry_block
            };
            return Ok((None, next_retry_block));
        }

        Ok((
            Some(TransactionCandidate {
                // Cheap: bumps the `Arc` refcount instead of deep-copying the account/storage.
                account: Arc::clone(account),
                notes: selected,
                chain_state,
            }),
            next_retry_block,
        ))
    }

    /// Execute a transaction candidate and mark notes as failed as required.
    ///
    /// Returns the new actor mode based on the execution result.
    ///
    /// Transient infrastructure failures (prover unreachable, RPC transport hiccup, RPC gRPC
    /// error) are retried inside [`execute::NtxContext::execute_transaction`].
    /// Any error reaching this method is therefore terminal for the candidate: the batch's notes
    /// are marked failed and the actor moves on.
    ///
    /// On a submission rejection (`NtxError::Submission`), `account` is refreshed in place from the
    /// DB before returning: the rejection usually means the in-memory account diverged from the
    /// committed chain, so the next selection must build on the authoritative state rather than
    /// re-declaring the stale commitment.
    #[miden_instrument(
        name = "ntx.actor.execute_transactions",
        fields(account.id = account_id),
    )]
    async fn execute_transactions(
        &self,
        account_id: AccountId,
        tx_candidate: TransactionCandidate,
        account: &mut Arc<Account>,
    ) -> anyhow::Result<ActorMode> {
        let block_num = tx_candidate.chain_state.chain_tip_header.block_num();

        // Execute the selected transaction.
        let context = execute::NtxContext::new(
            self.clients.prover.clone(),
            self.clients.rpc.clone(),
            self.state.script_cache.clone(),
            self.state.db.clone(),
            self.config.max_cycles,
            self.state.tx_args.clone(),
            self.config.request_backoff_initial,
            self.config.request_backoff_max,
        );

        let sponsored_notes = tx_candidate.notes.clone();
        // Failures of a sponsorship note are attributed to the feature note of its bundle:
        // sponsorship notes have no row in the `notes` table, so the feature note carries the
        // attempt tracking for its whole bundle.
        let sponsor_to_feature = tx_candidate.sponsor_to_feature_nullifier();
        let account_id = tx_candidate.account.id();
        let note_ids: Vec<_> = sponsored_notes
            .iter()
            .flat_map(|sponsored| {
                std::iter::once(sponsored.feature.as_note().id())
                    .chain(sponsored.sponsorships.iter().map(Note::id))
            })
            .collect();
        info!(
            target: LOG_TARGET,
            "executing network transaction",
            account.id = account_id,
            note.ids = note_ids.as_slice(),
            note.count = note_ids.len()
        );

        let execution_result = context.execute_transaction(tx_candidate).await;
        Ok(match execution_result {
            Ok(execute::NtxExecutionResult {
                tx_id,
                account_patch,
                failed_notes,
                deferred_notes,
                oversized_notes,
                fetched_scripts,
            }) => {
                // `filter_notes` has already partitioned the failed notes:
                // - `deferred_notes` were dropped only because the combined per-tx cycle budget was
                //   exhausted but are consumable on their own. They are left un-penalized so
                //   `available_notes` re-selects them next round, letting a large note land in its
                //   own transaction once its batch-mates commit.
                // - `oversized_notes` exceed the per-tx cycle budget on their own and can never be
                //   consumed. They are discarded immediately so they stop being re-selected.
                // - `failed_notes` are genuine consumability failures and are penalized as usual.
                info!(
                    target: LOG_TARGET,
                    "network transaction executed",
                    account.id = account_id,
                    transaction.id = tx_id,
                    note.failed.count = failed_notes.len(),
                    note.deferred.count = deferred_notes.len(),
                    note.oversized.count = oversized_notes.len()
                );
                self.cache_note_scripts(fetched_scripts).await;

                log_deferred_notes(deferred_notes);

                // Only feature notes are discarded permanently. An oversized sponsorship (its
                // isolated re-check runs the reclaim path, so this is unexpected) is charged to its
                // feature note as a regular failure instead: the feature itself may still be
                // consumable with a different sponsorship.
                let (oversized_sponsorships, oversized_features): (Vec<_>, Vec<_>) =
                    oversized_notes
                        .into_iter()
                        .partition(|f| sponsor_to_feature.contains_key(&f.note().id()));

                let mut to_penalize = failed_notes;
                to_penalize.extend(oversized_sponsorships);
                let failed_notes = attribute_failed_notes(to_penalize, &sponsor_to_feature);
                self.mark_notes_failed(&failed_notes, block_num).await;

                let nullifiers = log_oversized_notes(oversized_features);
                self.discard_notes(&nullifiers, block_num).await;

                // A non-empty successful set is guaranteed by `filter_notes` (it returns
                // `AllNotesFailed` otherwise), so a transaction was always submitted here and
                // carries real work to wait for.
                ActorMode::WaitForBlock {
                    submitted_tx_id: tx_id,
                    submitted_at: block_num,
                    pending_patch: account_patch,
                }
            },
            // Transaction execution failed.
            Err(err) => {
                error!(
                    &err,
                    target: LOG_TARGET,
                    "network transaction failed",
                    account.id = account_id,
                    note.ids = note_ids.as_slice()
                );

                // A rejected submission (e.g. an account-commitment mismatch) means our in-memory
                // account has diverged from the committed chain. Reload it from the DB below so the
                // next selection builds on the authoritative state instead of re-declaring the same
                // stale commitment. Resumption is gated on the next committed block by
                // `NoViableNotes`, so this cannot hot-loop.
                let submission_rejected = matches!(err, execute::NtxError::Submission(_));

                // For `AllNotesFailed`, use the per-note errors which contain the specific reason
                // each note failed (e.g. consumability check details). Whole-transaction errors are
                // recorded against the feature notes only: sponsorships have no row in the `notes`
                // table.
                let failed_notes: Vec<_> = match err {
                    execute::NtxError::AllNotesFailed(per_note) => {
                        attribute_failed_notes(per_note, &sponsor_to_feature)
                    },
                    other => {
                        let error: NoteError = Arc::new(other);
                        sponsored_notes
                            .iter()
                            .map(|sponsored| {
                                let feature = sponsored.feature.as_note();
                                info!(
                                    error.as_ref(),
                                    target: LOG_TARGET,
                                    "note failed: transaction execution error",
                                    note.id = feature.id(),
                                    note.nullifier = feature.nullifier()
                                );
                                (feature.nullifier(), error.clone())
                            })
                            .collect()
                    },
                };
                self.mark_notes_failed(&failed_notes, block_num).await;

                if submission_rejected {
                    if let Some(latest) = self
                        .state
                        .db
                        .get_account(self.account_id)
                        .await
                        .context("failed to reload account after a rejected submission")?
                    {
                        info!(
                            target: LOG_TARGET,
                            "reloaded account from the database after a rejected submission",
                            account.id = account_id
                        );
                        *account = Arc::new(latest);
                    }
                }

                ActorMode::NoViableNotes
            },
        })
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
        // Avoid an empty coordinator round-trip (and DB write-transaction) on the common
        // no-failures path.
        if failed_notes.is_empty() {
            return;
        }
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

    /// Sends a request to the coordinator to discard notes (mark them permanently unconsumable) and
    /// waits for the DB write to complete. Like [`Self::mark_notes_failed`], the acknowledgement
    /// prevents the actor from re-selecting the notes before the write lands.
    async fn discard_notes(&self, nullifiers: &[Nullifier], block_num: BlockNumber) {
        // Avoid an empty coordinator round-trip (and DB write-transaction) on the common
        // no-oversized-notes path.
        if nullifiers.is_empty() {
            return;
        }
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if self
            .request
            .send(ActorRequest::NotesDiscarded {
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

/// Logs each note discarded for exceeding the per-tx cycle budget on its own and returns their
/// nullifiers.
///
/// These notes were confirmed (by an isolation re-check in `filter_notes`) to need more than the
/// entire per-tx cycle budget for themselves, so they can never be consumed and are marked
/// permanently unconsumable rather than retried.
fn log_oversized_notes(oversized: Vec<FailedNote>) -> Vec<Nullifier> {
    oversized
        .into_iter()
        .map(|note| {
            warn!(
                target: LOG_TARGET,
                "note discarded: exceeds the per-tx cycle budget on its own and can never be consumed",
                note.id = note.note().id(),
                note.nullifier = note.note().nullifier(),
                note.execution_cycles = format_opt(note.num_cycles().as_ref())
            );
            note.note().nullifier()
        })
        .collect()
}

/// Logs each note deferred because the combined per-tx cycle budget was exhausted.
///
/// These notes are individually consumable and are intentionally *not* penalized (no
/// `(nullifier, error)` pairs are returned), so they remain eligible for selection in a subsequent
/// round with their `attempt_count` untouched.
fn log_deferred_notes(deferred: Vec<FailedNote>) {
    for note in deferred {
        info!(
            target: LOG_TARGET,
            "note deferred: exceeded per-tx cycle budget, will retry next round",
            note.id = note.note().id(),
            note.nullifier = note.note().nullifier(),
            note.execution_cycles = format_opt(note.num_cycles().as_ref())
        );
    }
}

/// Logs each failed note and returns `(nullifier, error)` pairs keyed by the nullifier the failure
/// is recorded under: a feature note fails under its own nullifier, while a sponsorship's failure
/// is charged to the feature note of its bundle (sponsorship notes have no row in the `notes`
/// table). Multiple failures attributed to the same feature note collapse to a single entry, so a
/// bundle never burns more than one attempt per round.
fn attribute_failed_notes(
    failed: Vec<FailedNote>,
    sponsor_to_feature: &HashMap<NoteId, Nullifier>,
) -> Vec<(Nullifier, NoteError)> {
    let mut seen = HashSet::new();
    let mut attributed = Vec::new();
    for f in failed {
        let error_msg = f.error().as_report();
        info!(
            f.error(),
            target: LOG_TARGET,
            "note failed: consumability check",
            note.id = f.note().id(),
            note.nullifier = f.note().nullifier()
        );
        let nullifier = sponsor_to_feature
            .get(&f.note().id())
            .copied()
            .unwrap_or_else(|| f.note().nullifier());
        if seen.insert(nullifier) {
            let error: NoteError = Arc::new(std::io::Error::other(error_msg));
            attributed.push((nullifier, error));
        }
    }
    attributed
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use miden_protocol::account::{Account, AccountPatch, AccountStoragePatch, AccountVaultPatch};
    use miden_protocol::{Felt, ONE};
    use tokio::sync::watch;

    use super::*;
    use crate::test_utils::{mock_account, mock_network_account_id, mock_transaction_id};

    /// Builds a valid nonce-only [`AccountPatch`] that advances `account` by a single nonce.
    fn nonce_bump_patch(account: &Account) -> AccountPatch {
        AccountPatch::new(
            account.id(),
            AccountStoragePatch::default(),
            AccountVaultPatch::default(),
            None,
            Some(account.nonce() + ONE),
        )
        .expect("a nonce-only patch is valid")
    }

    /// Builds an actor wired to `db` for the given account.
    fn test_actor(db: &NtxDbReader, account: &Account) -> AccountActor {
        let ctx = AccountActorContext::test(db);
        AccountActor::new(account.id(), &ctx)
    }

    /// Builds an [`AccountView`] for driving `reevaluate_mode` directly.
    fn view(
        chain_tip: u32,
        last_committed_tx: Option<TransactionId>,
        notes_seen: u64,
    ) -> AccountView {
        AccountView {
            chain_tip: chain_tip.into(),
            last_committed_tx,
            notes_seen,
        }
    }

    /// When the submitted transaction lands (its id is the view's latest committed tx), the actor
    /// advances its in-memory account by exactly the patch the transaction produced.
    #[tokio::test]
    async fn landing_advances_in_memory_account_by_its_patch() {
        let (db, _dir) = crate::db::test_setup().await;
        let account = mock_account(mock_network_account_id());
        let submitted = mock_transaction_id(7);

        let patch = nonce_bump_patch(&account);
        let mut expected = account.clone();
        expected.apply_patch(&patch).unwrap();

        let actor = test_actor(&db, &account);
        let mut in_memory = Arc::new(account.clone());
        let mut notes_cursor = 0;
        // The view reports our submission as the account's latest committed transaction.
        let view = view(1, Some(submitted), 0);
        let mode = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::WaitForBlock {
                    submitted_tx_id: submitted,
                    submitted_at: 0_u32.into(),
                    pending_patch: patch,
                },
                &view,
                &mut notes_cursor,
                None,
            )
            .await
            .unwrap();

        assert!(matches!(mode, ActorMode::NotesAvailable), "a landed tx must resume selection");
        assert_eq!(
            in_memory.to_commitment(),
            expected.to_commitment(),
            "the in-memory account must be advanced by the landed tx's patch",
        );
    }

    /// While the submission has neither landed nor expired, the actor keeps waiting and leaves its
    /// in-memory account untouched.
    #[tokio::test]
    async fn pending_submission_keeps_waiting_without_touching_account() {
        let (db, _dir) = crate::db::test_setup().await;
        let account = mock_account(mock_network_account_id());

        // The view shows no committed tx for the account (submission has not landed) and a tip well
        // within `tx_expiration_delta` of the submission block, so it has not expired either.
        let actor = test_actor(&db, &account);
        let mut in_memory = Arc::new(account.clone());
        let mut notes_cursor = 0;
        let submitted = mock_transaction_id(7);
        let view = view(1, None, 0);
        let mode = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::WaitForBlock {
                    submitted_tx_id: submitted,
                    submitted_at: 0_u32.into(),
                    pending_patch: nonce_bump_patch(&account),
                },
                &view,
                &mut notes_cursor,
                None,
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

    /// An idle actor must not re-select (and so must not hit the DB) on a view that only advances
    /// the chain tip: no new notes arrived and no scheduled retry is due.
    #[tokio::test]
    async fn idle_actor_ignores_view_without_new_work() {
        let (db, _dir) = crate::db::test_setup().await;
        let account = mock_account(mock_network_account_id());
        let actor = test_actor(&db, &account);
        let mut in_memory = Arc::new(account.clone());
        let mut notes_cursor = 3;

        // notes_seen matches the cursor (no new notes) and there is no pending retry.
        let view = view(10, None, 3);
        let mode = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::NoViableNotes,
                &view,
                &mut notes_cursor,
                None,
            )
            .await
            .unwrap();

        assert!(
            matches!(mode, ActorMode::NoViableNotes),
            "no new notes and no due retry must leave the actor idle",
        );
        assert_eq!(notes_cursor, 3, "the cursor is untouched while the actor stays idle");
    }

    /// New notes (the view's counter moving past the local cursor) wake an idle actor.
    #[tokio::test]
    async fn new_notes_wake_idle_actor() {
        let (db, _dir) = crate::db::test_setup().await;
        let account = mock_account(mock_network_account_id());
        let actor = test_actor(&db, &account);
        let mut in_memory = Arc::new(account.clone());
        let mut notes_cursor = 3;

        let view = view(10, None, 4);
        let mode = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::NoViableNotes,
                &view,
                &mut notes_cursor,
                None,
            )
            .await
            .unwrap();

        assert!(matches!(mode, ActorMode::NotesAvailable), "a new note must trigger a re-select");
        assert_eq!(notes_cursor, 4, "the cursor advances to the observed note count");
    }

    /// A scheduled retry wakes an idle actor exactly when the chain tip reaches `next_retry_block`,
    /// and not before. This is how backoff/hint retries fire without a new note arriving.
    #[tokio::test]
    async fn due_retry_wakes_idle_actor_at_its_block() {
        let (db, _dir) = crate::db::test_setup().await;
        let account = mock_account(mock_network_account_id());
        let actor = test_actor(&db, &account);
        let mut in_memory = Arc::new(account.clone());

        // Tip below the retry block: stay idle.
        let mut notes_cursor = 0;
        let early = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::NoViableNotes,
                &view(9, None, 0),
                &mut notes_cursor,
                Some(10_u32.into()),
            )
            .await
            .unwrap();
        assert!(matches!(early, ActorMode::NoViableNotes), "a retry is not due before its block");

        // Tip reaches the retry block: re-select.
        let due = actor
            .reevaluate_mode(
                &mut in_memory,
                ActorMode::NoViableNotes,
                &view(10, None, 0),
                &mut notes_cursor,
                Some(10_u32.into()),
            )
            .await
            .unwrap();
        assert!(matches!(due, ActorMode::NotesAvailable), "a due retry must trigger a re-select");
    }

    /// The idle timeout must still fire while the coordinator keeps pushing a view every block. The
    /// coordinator updates every actor's view on every committed block, so a workless actor would
    /// never expire if updates reset the idle timer. The deadline is absolute and only pushed back
    /// by real work, so repeated view updates cannot keep a no-work actor resident indefinitely.
    #[tokio::test]
    async fn idle_timeout_fires_despite_repeated_view_updates() {
        let (db, _dir) = crate::db::test_setup().await;
        // A real network account with a populated allowlist, so re-evaluation on each wake reaches
        // a clean "no viable notes" outcome instead of erroring on a missing allowlist slot.
        let (account, _) = crate::test_utils::mock_network_account_update();
        let account_id = account.id();

        // Seed the committed account but no notes, so the actor starts and stays in NoViableNotes
        // with no pending retry: it remains genuinely note-less and the idle timer ticks.
        db.upsert_account_for_test(account_id, account.clone(), mock_transaction_id(1))
            .await
            .unwrap();

        let mut ctx = AccountActorContext::test(&db);
        // Short idle timeout keeps the test fast.
        ctx.config.idle_timeout = Duration::from_millis(300);

        let actor = AccountActor::new(account_id, &ctx);
        let (view_tx, view_rx) = watch::channel(view(0, None, 0));
        let semaphore = Arc::new(Semaphore::new(1));
        let handle = tokio::spawn(actor.run(semaphore, view_rx, CancellationToken::new()));

        // Push a view update far more often than the idle timeout, advancing only the chain tip (no
        // new notes), for longer than the test's deadline. With a relative timer every update would
        // restart it and the actor would never deactivate, failing the timeout below.
        let notifier = tokio::spawn(async move {
            loop {
                view_tx.send_modify(|v| v.chain_tip = v.chain_tip.child());
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("actor must deactivate on idle timeout despite repeated view updates")
            .expect("actor task should not panic");
        assert!(result.is_ok(), "idle deactivation is a clean shutdown");

        notifier.abort();
    }

    // SPONSORSHIP-AWARE SELECTION
    // ---------------------------------------------------------------------------------------------

    use crate::sponsorship::SponsorshipNote;
    use crate::test_utils::{
        mock_network_account_update,
        mock_single_target_note,
        mock_sponsorship,
        mock_sponsorship_note_with_faucet_and_amount,
        mock_sponsorship_with_amount,
    };

    /// Seeds a committed network account (with a populated allowlist) and returns its id together
    /// with the account itself.
    async fn seed_selection_account(db: &crate::db::NtxDbWriter) -> (AccountId, Account) {
        let (account, _) = mock_network_account_update();
        db.upsert_account_for_test(account.id(), account.clone(), mock_transaction_id(1))
            .await
            .unwrap();
        (account.id(), account)
    }

    /// Each selected bundle carries exactly the pending sponsorships of its feature note.
    #[tokio::test]
    async fn select_candidate_attaches_sponsorships_for_pending_notes() {
        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        let feature_a = mock_single_target_note(account_id, 1);
        let feature_b = mock_single_target_note(account_id, 2);
        db.insert_network_notes(vec![feature_a.clone(), feature_b.clone()])
            .await
            .unwrap();
        db.insert_sponsorship_notes(vec![
            mock_sponsorship(account_id, feature_a.as_note().id(), 3),
            mock_sponsorship(account_id, feature_a.as_note().id(), 4),
        ])
        .await
        .unwrap();

        let mut ctx = AccountActorContext::test(&db);
        ctx.config.max_notes_per_tx = NonZeroUsize::new(20).unwrap();
        let actor = AccountActor::new(account_id, &ctx);
        let chain_state = actor.state.chain.get_cloned();

        let (candidate, _) = actor.select_candidate(&Arc::new(account), chain_state).await.unwrap();
        let candidate = candidate.expect("both bundles are viable");

        assert_eq!(candidate.notes.len(), 2);
        for sponsored in &candidate.notes {
            if sponsored.feature.as_note().id() == feature_a.as_note().id() {
                assert_eq!(sponsored.sponsorships.len(), 2, "feature A carries its sponsorships");
            } else {
                assert!(sponsored.sponsorships.is_empty(), "feature B has no sponsorships");
            }
        }
    }

    /// A feature note with more pending sponsorships than the cap gets exactly the cap, and the
    /// slots go to the largest sponsorships.
    #[tokio::test]
    async fn select_candidate_caps_sponsorships_per_note() {
        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        let feature = mock_single_target_note(account_id, 1);
        db.insert_network_notes(vec![feature.clone()]).await.unwrap();
        db.insert_sponsorship_notes(
            (0..5)
                .map(|i| {
                    mock_sponsorship_with_amount(
                        account_id,
                        feature.as_note().id(),
                        10 + i,
                        u64::from(i + 1) * 100,
                    )
                })
                .collect(),
        )
        .await
        .unwrap();

        let mut ctx = AccountActorContext::test(&db);
        ctx.config.max_notes_per_tx = NonZeroUsize::new(20).unwrap();
        let actor = AccountActor::new(account_id, &ctx);
        let chain_state = actor.state.chain.get_cloned();

        let (candidate, _) = actor.select_candidate(&Arc::new(account), chain_state).await.unwrap();
        let candidate = candidate.expect("the bundle is viable");

        assert_eq!(candidate.notes.len(), 1);
        assert_eq!(candidate.notes[0].sponsorships.len(), MAX_SPONSORSHIPS_PER_NOTE);
        // The five pending sponsorships carry 100 through 500; the cap keeps the largest three.
        let amounts = candidate.notes[0]
            .sponsorships
            .iter()
            .map(|note| note.assets().as_slice()[0].unwrap_fungible().amount().as_u64())
            .collect::<Vec<_>>();
        assert_eq!(amounts, [500, 400, 300]);
    }

    /// Sponsorships carrying the wrong asset are removed before the cap is applied, so they cannot
    /// occupy slots that could hold valid sponsorships.
    #[tokio::test]
    async fn select_candidate_filters_wrong_fee_asset_before_cap() {
        use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;

        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        let feature = mock_single_target_note(account_id, 1);
        let feature_id = feature.as_note().id();
        let valid = mock_sponsorship_with_amount(account_id, feature_id, 2, 100);
        let wrong_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
        let invalid = (3..=5)
            .map(|seed| {
                SponsorshipNote::try_from(mock_sponsorship_note_with_faucet_and_amount(
                    account_id,
                    feature_id,
                    seed,
                    wrong_faucet,
                    u64::from(seed) * 10_000,
                ))
                .expect("wrong-asset sponsorship is structurally valid")
            })
            .collect::<Vec<_>>();

        db.insert_network_notes(vec![feature]).await.unwrap();
        db.insert_sponsorship_notes(std::iter::once(valid.clone()).chain(invalid).collect())
            .await
            .unwrap();

        let mut ctx = AccountActorContext::test(&db);
        ctx.config.max_notes_per_tx = NonZeroUsize::new(20).unwrap();
        let actor = AccountActor::new(account_id, &ctx);
        let chain_state = actor.state.chain.get_cloned();

        let (candidate, _) = actor.select_candidate(&Arc::new(account), chain_state).await.unwrap();
        let candidate = candidate.expect("the feature and its valid sponsorship are viable");

        assert_eq!(candidate.notes.len(), 1);
        assert_eq!(candidate.notes[0].sponsorships.len(), 1);
        assert_eq!(candidate.notes[0].sponsorships[0].id(), valid.id());
    }

    /// Bundles are packed atomically against the per-tx note budget: a bundle that does not fit is
    /// skipped as a whole, never split.
    #[tokio::test]
    async fn select_candidate_packs_bundles_atomically() {
        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        // Bundle A is three notes (feature + 2 sponsorships), bundle B is two: only one of them
        // fits a three-note budget.
        let feature_a = mock_single_target_note(account_id, 1);
        let feature_b = mock_single_target_note(account_id, 2);
        db.insert_network_notes(vec![feature_a.clone(), feature_b.clone()])
            .await
            .unwrap();
        db.insert_sponsorship_notes(vec![
            mock_sponsorship(account_id, feature_a.as_note().id(), 3),
            mock_sponsorship(account_id, feature_a.as_note().id(), 4),
            mock_sponsorship(account_id, feature_b.as_note().id(), 5),
        ])
        .await
        .unwrap();

        let mut ctx = AccountActorContext::test(&db);
        ctx.config.max_notes_per_tx = NonZeroUsize::new(3).unwrap();
        let actor = AccountActor::new(account_id, &ctx);
        let chain_state = actor.state.chain.get_cloned();

        let (candidate, _) = actor.select_candidate(&Arc::new(account), chain_state).await.unwrap();
        let candidate = candidate.expect("at least one bundle fits the budget");

        assert_eq!(candidate.notes.len(), 1, "only one whole bundle fits three note slots");
        assert!(candidate.num_notes() <= 3, "a bundle must never be split to fit");
        let sponsored = &candidate.notes[0];
        assert!(!sponsored.sponsorships.is_empty(), "the selected bundle keeps its sponsorships");
    }

    /// The canonical expiration script carries its delta in `TX_SCRIPT_ARGS`, so every delta shares
    /// a single script root (the one network accounts allowlist), while the args word encodes the
    /// delta in its first element.
    #[test]
    fn expiration_script_shares_root_and_encodes_delta_in_args() {
        let one = build_tx_args(NonZeroU16::new(1).unwrap());
        let thirty = build_tx_args(NonZeroU16::new(30).unwrap());
        let max = build_tx_args(NonZeroU16::MAX);

        // All deltas resolve to the single allowlistable root.
        let root = ExpirationTransactionScript::script_root();
        assert_eq!(one.tx_script().unwrap().root(), root);
        assert_eq!(thirty.tx_script().unwrap().root(), root);
        assert_eq!(max.tx_script().unwrap().root(), root);

        // The delta rides in the first element of the args word.
        assert_eq!(one.tx_script_args()[0], Felt::from(1_u16));
        assert_eq!(thirty.tx_script_args()[0], Felt::from(30_u16));
        assert_eq!(max.tx_script_args()[0], Felt::from(u16::MAX));
    }
}
