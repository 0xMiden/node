use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_proto::domain::note::{NetworkNote, SingleTargetNetworkNote};
use miden_protocol::account::delta::AccountUpdateDetails;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::actor::{AccountActor, AccountActorContext, AccountOrigin, ActorShutdownReason};
use crate::db::Db;

// ACTOR HANDLE
// ================================================================================================

/// Handle to account actors that are spawned by the coordinator.
#[derive(Clone)]
struct ActorHandle {
    notify: Arc<Notify>,
    cancel_token: CancellationToken,
}

impl ActorHandle {
    fn new(notify: Arc<Notify>, cancel_token: CancellationToken) -> Self {
        Self { notify, cancel_token }
    }
}

// COORDINATOR
// ================================================================================================

/// Coordinator for managing [`AccountActor`] instances, tasks, and notifications.
///
/// The `Coordinator` is the central orchestrator of the network transaction builder system.
/// It manages the lifecycle of account actors. Each actor is responsible for handling transactions
/// for a specific network account. The coordinator provides the following core
/// functionality:
///
/// ## Actor Management
/// - Spawns new [`AccountActor`] instances for network accounts as needed.
/// - Maintains a registry of active actors with their notification handles.
/// - Gracefully handles actor shutdown and cleanup when actors complete or fail.
/// - Monitors actor tasks through a join set to detect completion or errors.
///
/// ## Event Notification
/// - Notifies actors via [`Notify`] when state may have changed.
/// - The DB is the source of truth: actors re-evaluate their state from DB on notification.
/// - Notifications are coalesced: multiple notifications while an actor is busy result in a single
///   wake-up.
///
/// ## Resource Management
/// - Controls transaction concurrency across all network accounts using a semaphore.
/// - Prevents resource exhaustion by limiting simultaneous transaction processing.
///
/// ## Actor Lifecycle
/// - Actors that have been idle for longer than the idle timeout deactivate themselves.
/// - When an actor deactivates, the coordinator checks if a notification arrived just as the actor
///   timed out. If so, the actor is respawned immediately.
/// - Deactivated actors are re-spawned when [`Coordinator::send_targeted`] detects notes targeting
///   an account without an active actor.
///
/// The coordinator operates in an event-driven manner:
/// 1. Network accounts are registered and actors spawned as needed.
/// 2. Mempool events are written to DB, then actors are notified.
/// 3. Actor completion/failure events are monitored and handled.
/// 4. Failed or completed actors are cleaned up from the registry.
pub struct Coordinator {
    /// Mapping of network account IDs to their notification handles and cancellation tokens.
    ///
    /// This registry serves as the primary directory for notifying active account actors.
    /// When actors are spawned, they register their notification handle here. When events need
    /// to be broadcast, this registry is used to locate the appropriate actors. The registry is
    /// automatically cleaned up when actors complete their execution.
    actor_registry: HashMap<NetworkAccountId, ActorHandle>,

    /// Join set for managing actor tasks and monitoring their completion status.
    ///
    /// This join set allows the coordinator to wait for actor task completion and handle
    /// different shutdown scenarios. When an actor task completes (either successfully or
    /// due to an error), the corresponding entry is removed from the actor registry.
    actor_join_set: JoinSet<ActorShutdownReason>,

    /// Semaphore for controlling the maximum number of concurrent transactions across all network
    /// accounts.
    ///
    /// This shared semaphore prevents the system from becoming overwhelmed by limiting the total
    /// number of transactions that can be processed simultaneously across all account actors.
    /// Each actor must acquire a permit from this semaphore before processing a transaction,
    /// ensuring fair resource allocation and system stability under load.
    semaphore: Arc<Semaphore>,

    /// Database for persistent state.
    db: Db,

    /// Tracks the number of crashes per account actor.
    ///
    /// When an actor shuts down due to a DB error, its crash count is incremented. Once
    /// the count reaches `max_actor_crashes`, the account is blacklisted and no new actor
    /// will be spawned for it.
    crash_counts: HashMap<NetworkAccountId, usize>,

    /// Maximum number of crashes an account actor is allowed before being blacklisted.
    max_actor_crashes: usize,
}

impl Coordinator {
    /// Creates a new coordinator with the specified maximum number of inflight transactions
    /// and the crash threshold for account blacklisting.
    pub fn new(max_inflight_transactions: usize, max_actor_crashes: usize, db: Db) -> Self {
        Self {
            actor_registry: HashMap::new(),
            actor_join_set: JoinSet::new(),
            semaphore: Arc::new(Semaphore::new(max_inflight_transactions)),
            db,
            crash_counts: HashMap::new(),
            max_actor_crashes,
        }
    }

    /// Spawns a new actor to manage the state of the provided network account.
    ///
    /// This method creates a new [`AccountActor`] instance for the specified account origin
    /// and adds it to the coordinator's management system. The actor will be responsible for
    /// processing transactions and managing state for the network account.
    #[tracing::instrument(name = "ntx.builder.spawn_actor", skip(self, origin, actor_context))]
    pub fn spawn_actor(&mut self, origin: AccountOrigin, actor_context: &AccountActorContext) {
        let account_id = origin.id();

        // Skip spawning if the account has been blacklisted due to repeated crashes.
        if let Some(&count) = self.crash_counts.get(&account_id) {
            if count >= self.max_actor_crashes {
                tracing::warn!(
                    %account_id,
                    crash_count = count,
                    "Account blacklisted due to repeated crashes, skipping actor spawn"
                );
                return;
            }
        }

        // If an actor already exists for this account ID, something has gone wrong.
        if let Some(handle) = self.actor_registry.remove(&account_id) {
            tracing::error!(
                account_id = %account_id,
                "Account actor already exists"
            );
            handle.cancel_token.cancel();
        }

        let notify = Arc::new(Notify::new());
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let actor = AccountActor::new(origin, actor_context, notify.clone(), cancel_token.clone());
        let handle = ActorHandle::new(notify, cancel_token);

        // Run the actor. Actor reads state from DB on startup.
        let semaphore = self.semaphore.clone();
        self.actor_join_set.spawn(Box::pin(actor.run(semaphore)));

        self.actor_registry.insert(account_id, handle);
        tracing::info!(account_id = %account_id, "Created actor for account prefix");
    }

    /// Notifies all active account actors that state may have changed.
    ///
    /// Each actor will re-evaluate its state from the DB on the next iteration of its run loop.
    /// Notifications are coalesced: multiple notifications while an actor is busy result in a
    /// single wake-up.
    pub fn broadcast(&self) {
        for handle in self.actor_registry.values() {
            handle.notify.notify_one();
        }
    }

    /// Waits for the next actor to complete and processes the shutdown reason.
    ///
    /// This method monitors the join set for actor task completion and handles
    /// different shutdown scenarios appropriately. It's designed to be called
    /// in a loop to continuously monitor and manage actor lifecycles.
    ///
    /// If no actors are currently running, this method will wait indefinitely until
    /// new actors are spawned. This prevents busy-waiting when the coordinator is idle.
    ///
    /// Returns `Some(account_id)` if a timed-out actor should be respawned (because a
    /// notification arrived just as it timed out), or `None` otherwise.
    pub async fn next(&mut self) -> anyhow::Result<Option<NetworkAccountId>> {
        let actor_result = self.actor_join_set.join_next().await;
        match actor_result {
            Some(Ok(shutdown_reason)) => match shutdown_reason {
                ActorShutdownReason::Cancelled(account_id) => {
                    // Do not remove the actor from the registry, as it may be re-spawned.
                    // The coordinator should always remove actors immediately after cancellation.
                    tracing::info!(account_id = %account_id, "Account actor cancelled");
                    Ok(None)
                },
                ActorShutdownReason::SemaphoreFailed(err) => Err(err).context("semaphore failed"),
                ActorShutdownReason::DbError(account_id) => {
                    let count = self.crash_counts.entry(account_id).or_insert(0);
                    *count += 1;
                    tracing::error!(
                        %account_id,
                        crash_count = *count,
                        "Account actor shut down due to DB error"
                    );
                    Ok(None)
                },
                ActorShutdownReason::IdleTimeout(account_id) => {
                    tracing::info!(account_id = %account_id, "Account actor shut down due to idle timeout");

                    // Remove the actor from the registry, but check if a notification arrived
                    // just as the actor timed out. If so, the caller should respawn it.
                    let should_respawn =
                        self.actor_registry.remove(&account_id).is_some_and(|handle| {
                            let notified = handle.notify.notified();
                            tokio::pin!(notified);
                            notified.enable()
                        });

                    Ok(should_respawn.then_some(account_id))
                },
            },
            Some(Err(err)) => {
                tracing::error!(err = %err, "actor task failed");
                Ok(None)
            },
            None => {
                // There are no actors to wait for. Wait indefinitely until actors are spawned.
                std::future::pending().await
            },
        }
    }

    /// Notifies account actors that are affected by a `TransactionAdded` event.
    ///
    /// Only actors that are currently active are notified. Since event effects are already
    /// persisted in the DB by `write_event()`, actors that spawn later read their state from the
    /// DB and do not need predating events.
    ///
    /// Returns account IDs of note targets that do not have active actors (e.g. previously
    /// deactivated due to sterility). The caller can use this to re-activate actors for those
    /// accounts.
    pub fn send_targeted(&self, event: &MempoolEvent) -> Vec<NetworkAccountId> {
        let mut target_account_ids = HashSet::new();
        let mut inactive_targets = Vec::new();

        if let MempoolEvent::TransactionAdded { network_notes, account_delta, .. } = event {
            // We need to inform the account if it was updated. This lets it know that its own
            // transaction has been applied, and in the future also resolves race conditions with
            // external network transactions (once these are allowed).
            if let Some(AccountUpdateDetails::Delta(delta)) = account_delta {
                let account_id = delta.id();
                if account_id.is_network() {
                    let network_account_id =
                        account_id.try_into().expect("account is network account");
                    if self.actor_registry.contains_key(&network_account_id) {
                        target_account_ids.insert(network_account_id);
                    }
                }
            }

            // Determine target actors for each note.
            for note in network_notes {
                let NetworkNote::SingleTarget(note) = note;
                let network_account_id = note.account_id();
                if self.actor_registry.contains_key(&network_account_id) {
                    target_account_ids.insert(network_account_id);
                } else {
                    inactive_targets.push(network_account_id);
                }
            }
        }
        // Notify target actors.
        for account_id in &target_account_ids {
            if let Some(handle) = self.actor_registry.get(account_id) {
                handle.notify.notify_one();
            }
        }

        inactive_targets
    }

    /// Writes mempool event effects to the database.
    ///
    /// This must be called BEFORE sending notifications to actors. For `TransactionsReverted`,
    /// returns the list of account IDs whose creation was reverted.
    pub async fn write_event(
        &self,
        event: &MempoolEvent,
    ) -> Result<Vec<NetworkAccountId>, DatabaseError> {
        match event {
            MempoolEvent::TransactionAdded {
                id,
                nullifiers,
                network_notes,
                account_delta,
            } => {
                let notes: Vec<SingleTargetNetworkNote> = network_notes
                    .iter()
                    .map(|n| {
                        let NetworkNote::SingleTarget(note) = n;
                        note.clone()
                    })
                    .collect();

                self.db
                    .handle_transaction_added(*id, account_delta.clone(), notes, nullifiers.clone())
                    .await?;
                Ok(Vec::new())
            },
            MempoolEvent::BlockCommitted { header, txs } => {
                self.db
                    .handle_block_committed(
                        txs.clone(),
                        header.block_num(),
                        header.as_ref().clone(),
                    )
                    .await?;
                Ok(Vec::new())
            },
            MempoolEvent::TransactionsReverted(tx_ids) => {
                self.db.handle_transactions_reverted(tx_ids.iter().copied().collect()).await
            },
        }
    }

    /// Cancels an actor by its account ID.
    pub fn cancel_actor(&mut self, account_id: &NetworkAccountId) {
        if let Some(handle) = self.actor_registry.remove(account_id) {
            handle.cancel_token.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::time::Duration;

    use miden_node_proto::domain::mempool::MempoolEvent;
    use miden_node_proto::domain::note::NetworkNote;
    use miden_node_utils::lru_cache::LruCache;
    use tokio::sync::{RwLock, mpsc};
    use url::Url;

    use super::*;
    use crate::actor::{AccountActorContext, AccountOrigin};
    use crate::chain_state::ChainState;
    use crate::clients::StoreClient;
    use crate::db::Db;
    use crate::test_utils::*;

    /// Creates a coordinator with default settings backed by a temp DB.
    async fn test_coordinator() -> (Coordinator, tempfile::TempDir) {
        let (db, dir) = Db::test_setup().await;
        (Coordinator::new(4, 10, db), dir)
    }

    /// Creates a minimal `AccountActorContext` suitable for unit tests.
    ///
    /// The URLs are fake and actors spawned with this context will fail on their first gRPC call,
    /// but this is sufficient for testing coordinator logic (registry, blacklisting, etc.).
    fn test_actor_context(db: &Db) -> AccountActorContext {
        use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};

        let url = Url::parse("http://127.0.0.1:1").unwrap();
        let block_header = mock_block_header(0_u32.into());
        let chain_mmr = PartialMmr::from_peaks(MmrPeaks::new(Forest::new(0), vec![]).unwrap());
        let chain_state = Arc::new(RwLock::new(ChainState::new(block_header, chain_mmr)));
        let (request_tx, _request_rx) = mpsc::channel(1);

        AccountActorContext {
            block_producer_url: url.clone(),
            validator_url: url.clone(),
            tx_prover_url: None,
            chain_state,
            store: StoreClient::new(url),
            script_cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
            max_notes_per_tx: NonZeroUsize::new(1).unwrap(),
            max_note_attempts: 1,
            idle_timeout: Duration::from_secs(60),
            db: db.clone(),
            request_tx,
        }
    }

    /// Registers a dummy actor handle (no real actor task) in the coordinator's registry.
    fn register_dummy_actor(coordinator: &mut Coordinator, account_id: NetworkAccountId) {
        let notify = Arc::new(Notify::new());
        let cancel_token = CancellationToken::new();
        coordinator
            .actor_registry
            .insert(account_id, ActorHandle::new(notify, cancel_token));
    }

    // SEND TARGETED TESTS
    // ============================================================================================

    #[tokio::test]
    async fn send_targeted_returns_inactive_targets() {
        let (mut coordinator, _dir) = test_coordinator().await;

        let active_id = mock_network_account_id();
        let inactive_id = mock_network_account_id_seeded(42);

        // Only register the active account.
        register_dummy_actor(&mut coordinator, active_id);

        let note_active = mock_single_target_note(active_id, 10);
        let note_inactive = mock_single_target_note(inactive_id, 20);

        let event = MempoolEvent::TransactionAdded {
            id: mock_tx_id(1),
            nullifiers: vec![],
            network_notes: vec![
                NetworkNote::SingleTarget(note_active),
                NetworkNote::SingleTarget(note_inactive),
            ],
            account_delta: None,
        };

        let inactive_targets = coordinator.send_targeted(&event);

        assert_eq!(inactive_targets.len(), 1);
        assert_eq!(inactive_targets[0], inactive_id);
    }

    // BLACKLIST TESTS
    // ============================================================================================

    #[tokio::test]
    async fn spawn_actor_skips_blacklisted_account() {
        let (db, _dir) = Db::test_setup().await;
        let max_crashes = 3;
        let mut coordinator = Coordinator::new(4, max_crashes, db.clone());
        let actor_context = test_actor_context(&db);

        let account_id = mock_network_account_id();

        // Simulate the account having reached the crash threshold.
        coordinator.crash_counts.insert(account_id, max_crashes);

        coordinator.spawn_actor(AccountOrigin::Store(account_id), &actor_context);

        assert!(
            !coordinator.actor_registry.contains_key(&account_id),
            "Blacklisted account should not have an actor in the registry"
        );
    }

    #[tokio::test]
    async fn spawn_actor_allows_below_threshold() {
        let (db, _dir) = Db::test_setup().await;
        let max_crashes = 3;
        let mut coordinator = Coordinator::new(4, max_crashes, db.clone());
        let actor_context = test_actor_context(&db);

        let account_id = mock_network_account_id();

        // Set crash count below the threshold.
        coordinator.crash_counts.insert(account_id, max_crashes - 1);

        coordinator.spawn_actor(AccountOrigin::Store(account_id), &actor_context);

        assert!(
            coordinator.actor_registry.contains_key(&account_id),
            "Account below crash threshold should have an actor in the registry"
        );
    }
}
