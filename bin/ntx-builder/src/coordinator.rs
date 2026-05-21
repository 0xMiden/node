use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::actor::{AccountActor, AccountActorContext};
use crate::committed_block::CommittedBlockEffects;
use crate::db::Db;

// APPLY BLOCK RESULT
// ================================================================================================

/// Result of applying a committed block to the database.
pub struct ApplyBlockResult {
    /// Accounts that should be notified of state changes.
    pub accounts_to_notify: Vec<NetworkAccountId>,
}

// ACTOR HANDLE
// ================================================================================================

/// Handle to an account actor spawned by the coordinator.
#[derive(Clone)]
struct ActorHandle {
    /// [`Notify`] shared with the actor. The coordinator calls [`Notify::notify_one`] when DB state
    /// relevant to the actor may have changed, the actor awaits [`Notify::notified`] and
    /// re-evaluates its state on wake-up.
    notify: Arc<Notify>,
}

impl ActorHandle {
    fn new(notify: Arc<Notify>) -> Self {
        Self { notify }
    }

    /// Signals the actor that DB state may have changed. Notifications coalesce when one is already
    /// pending.
    fn notify(&self) {
        self.notify.notify_one();
    }

    /// Returns `true` if a notification is queued but not yet consumed by the actor.
    ///
    /// Used after an actor has shut down to detect the race where a notification arrived just
    /// as the actor timed out. If so, the coordinator should respawn the actor.
    fn has_pending_notification(&self) -> bool {
        use futures::FutureExt;
        if self.notify.notified().now_or_never().is_some() {
            // Restore the permit so the respawned actor still sees the notification.
            self.notify.notify_one();
            true
        } else {
            false
        }
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
/// - Notifies actors via a shared [`Notify`] when state may have changed.
/// - The DB is the source of truth: actors re-evaluate their state from DB on notification.
/// - Notifications are coalesced: [`Notify`] stores at most one permit, so multiple notifications
///   while an actor is busy result in a single wake-up.
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
/// 2. Committed block effects are written to DB, then actors are notified.
/// 3. Actor completion/failure events are monitored and handled.
/// 4. Failed or completed actors are cleaned up from the registry.
pub struct Coordinator {
    /// Mapping of network account IDs to their notification handles.
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
    actor_join_set: JoinSet<(NetworkAccountId, anyhow::Result<()>)>,

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
    /// the count reaches `max_account_crashes`, the account is deactivated and no new actor
    /// will be spawned for it.
    crash_counts: HashMap<NetworkAccountId, usize>,

    /// Maximum number of crashes an account actor is allowed before being deactivated.
    max_account_crashes: usize,
}

impl Coordinator {
    /// Creates a new coordinator with the specified maximum number of inflight transactions and the
    /// crash threshold for account deactivation.
    pub fn new(max_inflight_transactions: usize, max_account_crashes: usize, db: Db) -> Self {
        Self {
            actor_registry: HashMap::new(),
            actor_join_set: JoinSet::new(),
            semaphore: Arc::new(Semaphore::new(max_inflight_transactions)),
            db,
            crash_counts: HashMap::new(),
            max_account_crashes,
        }
    }

    /// Spawns a new actor to manage the state of the provided network account.
    ///
    /// This method creates a new [`AccountActor`] instance for the specified account origin
    /// and adds it to the coordinator's management system. The actor will be responsible for
    /// processing transactions and managing state for the network account.
    #[tracing::instrument(name = "ntx.builder.spawn_actor", skip(self, actor_context))]
    pub fn spawn_actor(
        &mut self,
        account_id: NetworkAccountId,
        actor_context: &AccountActorContext,
    ) {
        // Skip spawning if the account has been deactivated due to repeated crashes.
        if let Some(&count) = self.crash_counts.get(&account_id) {
            if count >= self.max_account_crashes {
                tracing::warn!(
                    account.id = %account_id,
                    crash_count = count,
                    "Account deactivated due to repeated crashes, skipping actor spawn"
                );
                return;
            }
        }

        // If an actor already exists for this account ID, something has gone wrong. Reject the
        // spawn rather than replacing.
        if self.actor_registry.contains_key(&account_id) {
            tracing::error!(
                account_id = %account_id,
                "Account actor already exists"
            );
            return;
        }

        let notify = Arc::new(Notify::new());
        let actor = AccountActor::new(account_id, actor_context, notify.clone());
        let handle = ActorHandle::new(notify);

        // Run the actor. Actor reads state from DB on startup.
        let semaphore = self.semaphore.clone();
        self.actor_join_set
            .spawn(Box::pin(async move { (account_id, actor.run(semaphore).await) }));

        self.actor_registry.insert(account_id, handle);
        tracing::info!(account_id = %account_id, "Created actor for account prefix");
    }

    /// Returns `true` if an actor is currently registered for the given account.
    pub fn has_actor(&self, account_id: NetworkAccountId) -> bool {
        self.actor_registry.contains_key(&account_id)
    }

    /// Notifies specific account actors that state may have changed.
    ///
    /// Only actors that are currently active are notified. Each actor will re-evaluate its state
    /// from the DB on the next iteration of its run loop. Notifications are coalesced: multiple
    /// notifications while an actor is busy result in a single wake-up.
    pub fn notify_accounts(&self, account_ids: &[NetworkAccountId]) {
        for account_id in account_ids {
            if let Some(handle) = self.actor_registry.get(account_id) {
                handle.notify();
            }
        }
    }

    /// Notifies every active actor that a new block has been applied.
    ///
    /// Called once per committed block so that actors waiting on their own submitted transaction
    /// (in [`ActorMode::WaitForNextBlock`](crate::actor::ActorMode)) reliably wake up even when
    /// the block did not touch their account.
    pub fn notify_all(&self) {
        for handle in self.actor_registry.values() {
            handle.notify();
        }
    }

    /// Waits for the next actor to complete and handles the outcome.
    ///
    /// This method monitors the join set for actor task completion and handles
    /// different shutdown scenarios appropriately. It's designed to be called
    /// in a loop to continuously monitor and manage actor lifecycles.
    ///
    /// If no actors are currently running, this method will wait indefinitely until
    /// new actors are spawned. This prevents busy-waiting when the coordinator is idle.
    ///
    /// Returns `Some(account_id)` if an actor should be respawned (because a
    /// notification arrived just as it shut down), or `None` otherwise.
    pub async fn next(&mut self) -> anyhow::Result<Option<NetworkAccountId>> {
        let actor_result = self.actor_join_set.join_next().await;
        match actor_result {
            Some(Ok((account_id, Ok(())))) => {
                // Actor shut down intentionally (idle timeout or account removed). Remove from
                // registry and check if a notification arrived just as it shut down. If so, the
                // caller should respawn it.
                let should_respawn = self
                    .actor_registry
                    .remove(&account_id)
                    .is_some_and(|handle| handle.has_pending_notification());

                Ok(should_respawn.then_some(account_id))
            },
            Some(Ok((account_id, Err(err)))) => {
                // Actor crashed. Increment crash counter.
                let count = self.crash_counts.entry(account_id).or_insert(0);
                *count += 1;
                tracing::error!(
                    account.id = %account_id,
                    "Account actor crashed: {err:#}"
                );
                self.actor_registry.remove(&account_id);
                Ok(None)
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

    /// Notifies account actors affected by newly created network notes or account updates in a
    /// committed block.
    ///
    /// Only actors that are currently active are notified. Since the block effects are already
    /// persisted in the DB by `apply_block()`, actors that spawn later read their state from the
    /// DB and do not need to replay predating blocks.
    ///
    /// Returns account IDs of note targets that do not have active actors (e.g. previously
    /// deactivated due to sterility). The caller can use this to re-activate actors for those
    /// accounts.
    pub fn send_targeted(&self, effects: &CommittedBlockEffects) -> Vec<NetworkAccountId> {
        let mut target_account_ids = HashSet::new();
        let mut inactive_targets = Vec::new();

        // Notify any active actor whose network account was updated in this block.
        for (account_id, _details) in &effects.network_account_updates {
            if self.actor_registry.contains_key(account_id) {
                target_account_ids.insert(*account_id);
            }
        }

        // Determine target actors for each newly created network note.
        for note in &effects.network_notes {
            let account = NetworkAccountId::try_from(note.target_account_id())
                .expect("network note target account should be a network account");

            if self.actor_registry.contains_key(&account) {
                target_account_ids.insert(account);
            } else {
                inactive_targets.push(account);
            }
        }

        // Notify target actors.
        for account_id in &target_account_ids {
            if let Some(handle) = self.actor_registry.get(account_id) {
                handle.notify();
            }
        }

        inactive_targets
    }

    /// Applies a committed block's effects to the database.
    ///
    /// Persists the new chain MMR atomically with the block effects. Must be called BEFORE
    /// sending notifications to actors. Returns an [`ApplyBlockResult`] with the accounts that
    /// should be notified.
    pub async fn apply_block(
        &self,
        effects: &CommittedBlockEffects,
        chain_mmr: PartialMmr,
    ) -> Result<ApplyBlockResult, DatabaseError> {
        let affected_accounts = self.db.apply_committed_block(effects.clone(), chain_mmr).await?;
        Ok(ApplyBlockResult { accounts_to_notify: affected_accounts })
    }
}

#[cfg(test)]
impl Coordinator {
    /// Creates a coordinator with default settings backed by a temp DB.
    pub async fn test() -> (Self, tempfile::TempDir) {
        let (db, dir) = Db::test_setup().await;
        (Self::new(4, 10, db), dir)
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    use super::*;
    use crate::actor::AccountActorContext;
    use crate::db::Db;
    use crate::test_utils::*;

    /// Registers a dummy actor handle (no real actor task) in the coordinator's registry.
    fn register_dummy_actor(coordinator: &mut Coordinator, account_id: NetworkAccountId) {
        let notify = Arc::new(Notify::new());
        coordinator.actor_registry.insert(account_id, ActorHandle::new(notify));
    }

    // SEND TARGETED TESTS
    // ============================================================================================

    #[tokio::test]
    async fn send_targeted_returns_inactive_targets() {
        let (mut coordinator, _dir) = Coordinator::test().await;

        let active_id = mock_network_account_id();
        let inactive_id = mock_network_account_id_seeded(42);

        // Only register the active account.
        register_dummy_actor(&mut coordinator, active_id);

        let note_active = mock_single_target_note(active_id, 10);
        let note_inactive = mock_single_target_note(inactive_id, 20);

        let effects = CommittedBlockEffects {
            header: mock_block_header(BlockNumber::from(1)),
            network_notes: vec![note_active, note_inactive],
            nullifiers: vec![],
            network_account_updates: vec![],
        };

        let inactive_targets = coordinator.send_targeted(&effects);

        assert_eq!(inactive_targets.len(), 1);
        assert_eq!(inactive_targets[0], inactive_id);
    }

    // DEACTIVATED ACCOUNTS
    // ============================================================================================

    #[tokio::test]
    async fn spawn_actor_skips_deactivated_account() {
        let (db, _dir) = Db::test_setup().await;
        let max_crashes = 3;
        let mut coordinator = Coordinator::new(4, max_crashes, db.clone());
        let actor_context = AccountActorContext::test(&db);

        let account_id = mock_network_account_id();

        // Simulate the account having reached the crash threshold.
        coordinator.crash_counts.insert(account_id, max_crashes);

        coordinator.spawn_actor(account_id, &actor_context);

        assert!(
            !coordinator.actor_registry.contains_key(&account_id),
            "Deactivated account should not have an actor in the registry"
        );
    }

    #[tokio::test]
    async fn spawn_actor_allows_below_threshold() {
        let (db, _dir) = Db::test_setup().await;
        let max_crashes = 3;
        let mut coordinator = Coordinator::new(4, max_crashes, db.clone());
        let actor_context = AccountActorContext::test(&db);

        let account_id = mock_network_account_id();

        // Set crash count below the threshold.
        coordinator.crash_counts.insert(account_id, max_crashes - 1);

        coordinator.spawn_actor(account_id, &actor_context);

        assert!(
            coordinator.actor_registry.contains_key(&account_id),
            "Account below crash threshold should have an actor in the registry"
        );
    }
}
