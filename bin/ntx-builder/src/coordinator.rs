use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use miden_protocol::account::AccountId;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::actor::{AccountActor, AccountActorContext};
use crate::committed_block::CommittedBlockEffects;

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

/// Lifecycle owner for [`AccountActor`] instances driven by committed blocks.
///
/// The coordinator owns the actor-side context (gRPC clients, shared chain state, script cache,
/// per-actor config), the actor task join set, and a registry mapping each network account to a
/// notify handle. The builder calls into the coordinator at two moments:
///
/// 1. At the catch-up boundary, to spawn one actor per account returned by
///    `Db::accounts_with_pending_notes()`.
/// 2. On every committed block in steady state, via [`Coordinator::handle_committed_block`], which
///    spawns missing actors for accounts that just received new network notes and wakes every
///    active actor so it can re-evaluate its state from the DB.
///
/// Notifications are coalesced through [`Notify`]: multiple wakes while an actor is busy
/// collapse into one. Actors that crash repeatedly are deactivated after `max_account_crashes`
/// failures.
pub struct Coordinator {
    /// Mapping of network account IDs to their notification handles.
    actor_registry: HashMap<AccountId, ActorHandle>,

    /// Join set tracking each spawned actor task; used to detect intentional shutdowns vs. crashes.
    actor_join_set: JoinSet<(AccountId, anyhow::Result<()>)>,

    /// Shared transaction-execution semaphore handed to each spawned actor.
    semaphore: Arc<Semaphore>,

    /// Shared resources needed to spawn an actor. Stored on the coordinator so spawns at runtime
    /// don't need the builder to plumb context through every call site.
    actor_context: AccountActorContext,

    /// Tracks the number of crashes per account actor.
    ///
    /// When an actor shuts down due to a DB error, its crash count is incremented. Once
    /// the count reaches `max_account_crashes`, the account is deactivated and no new actor
    /// will be spawned for it.
    crash_counts: HashMap<AccountId, usize>,

    /// Maximum number of crashes an account actor is allowed before being deactivated.
    max_account_crashes: usize,
}

impl Coordinator {
    /// Creates a new coordinator with the specified transaction concurrency limit and the per-
    /// account crash threshold.
    pub fn new(
        max_inflight_transactions: usize,
        max_account_crashes: usize,
        actor_context: AccountActorContext,
    ) -> Self {
        Self {
            actor_registry: HashMap::new(),
            actor_join_set: JoinSet::new(),
            semaphore: Arc::new(Semaphore::new(max_inflight_transactions)),
            actor_context,
            crash_counts: HashMap::new(),
            max_account_crashes,
        }
    }

    /// Spawns a new actor to manage the state of the provided network account.
    ///
    /// This method creates a new [`AccountActor`] instance for the specified account origin
    /// and adds it to the coordinator's management system. The actor will be responsible for
    /// processing transactions and managing state for the network account.
    #[tracing::instrument(name = "ntx.builder.spawn_actor", skip(self))]
    pub fn spawn_actor(&mut self, account_id: AccountId) {
        if let Some(&count) = self.crash_counts.get(&account_id)
            && count >= self.max_account_crashes
        {
            tracing::warn!(
                account.id = %account_id,
                crash_count = count,
                "Account deactivated due to repeated crashes, skipping actor spawn"
            );
            return;
        }

        if self.actor_registry.contains_key(&account_id) {
            tracing::error!(
                account.id = %account_id,
                "Account actor already exists",
            );
            return;
        }

        let notify = Arc::new(Notify::new());
        let actor = AccountActor::new(account_id, &self.actor_context, notify.clone());
        let handle = ActorHandle::new(notify);

        let semaphore = self.semaphore.clone();
        self.actor_join_set
            .spawn(Box::pin(async move { (account_id, actor.run(semaphore).await) }));

        self.actor_registry.insert(account_id, handle);
        tracing::info!(account.id = %account_id, "Created actor for account");
    }

    /// Reacts to a committed block: spawns actors for any newly-targeted network accounts and wakes
    /// every active actor so it can re-evaluate its state.
    pub fn handle_committed_block(&mut self, effects: &CommittedBlockEffects) {
        let mut targeted: HashSet<AccountId> = HashSet::new();
        for note in &effects.network_notes {
            targeted.insert(note.target_account_id());
        }

        for account_id in &targeted {
            if !self.actor_registry.contains_key(account_id) {
                self.spawn_actor(*account_id);
            }
        }

        for handle in self.actor_registry.values() {
            handle.notify();
        }
    }

    /// Waits for the next actor to complete and handles the outcome.
    ///
    /// Returns `Some(account_id)` if an actor should be respawned (because a notification arrived
    /// just as it shut down on idle timeout), or `None` otherwise. If no actors are currently
    /// running, this method waits indefinitely until new actors are spawned.
    pub async fn next(&mut self) -> anyhow::Result<Option<AccountId>> {
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
}

#[cfg(test)]
impl Coordinator {
    /// Creates a coordinator with default settings backed by a temp DB. Returns the coordinator,
    /// the temp dir holding the DB file, and the actor request receiver (drop it to discard, or
    /// drive it from the test to inspect actor requests).
    pub async fn test()
    -> (Self, tempfile::TempDir, tokio::sync::mpsc::Receiver<crate::actor::ActorRequest>) {
        use crate::db::Db;

        let (db, dir) = Db::test_setup().await;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let mut actor_context = AccountActorContext::test(&db);
        actor_context.request_tx = tx;
        (Self::new(4, 10, actor_context), dir, rx)
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::*;
    use crate::test_utils::*;

    /// Registers a dummy actor handle (no real actor task) in the coordinator's registry.
    fn register_dummy_actor(coordinator: &mut Coordinator, account_id: AccountId) {
        let notify = Arc::new(Notify::new());
        coordinator.actor_registry.insert(account_id, ActorHandle::new(notify));
    }

    #[tokio::test]
    async fn handle_committed_block_spawns_for_unknown_note_target() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let unknown_id = mock_network_account_id();
        let note = mock_single_target_note(unknown_id, 10);
        let effects = CommittedBlockEffects {
            header: mock_block_header(1_u32.into()),
            network_notes: vec![note],
            nullifiers: vec![],
            network_account_updates: vec![],
        };

        coordinator.handle_committed_block(&effects);

        assert!(
            coordinator.actor_registry.contains_key(&unknown_id),
            "previously-untouched account targeted by a note should get a fresh actor",
        );
    }

    #[tokio::test]
    async fn handle_committed_block_does_not_spawn_for_account_update_only() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let updated_id = mock_network_account_id();
        let effects = CommittedBlockEffects {
            header: mock_block_header(1_u32.into()),
            network_notes: vec![],
            nullifiers: vec![],
            network_account_updates: vec![(
                updated_id,
                miden_protocol::account::delta::AccountUpdateDetails::Private,
            )],
        };

        coordinator.handle_committed_block(&effects);

        assert!(
            !coordinator.actor_registry.contains_key(&updated_id),
            "an account update without a new note should not trigger an actor spawn",
        );
    }

    #[tokio::test]
    async fn spawn_actor_skips_deactivated_account() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let account_id = mock_network_account_id();
        coordinator.crash_counts.insert(account_id, coordinator.max_account_crashes);

        coordinator.spawn_actor(account_id);

        assert!(
            !coordinator.actor_registry.contains_key(&account_id),
            "deactivated account should not have an actor in the registry",
        );
    }

    #[tokio::test]
    async fn spawn_actor_allows_below_threshold() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let account_id = mock_network_account_id();
        coordinator
            .crash_counts
            .insert(account_id, coordinator.max_account_crashes.saturating_sub(1));

        coordinator.spawn_actor(account_id);

        assert!(
            coordinator.actor_registry.contains_key(&account_id),
            "account below crash threshold should have an actor in the registry",
        );
    }

    #[tokio::test]
    async fn handle_committed_block_notifies_existing_actors() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let bystander = mock_network_account_id();
        register_dummy_actor(&mut coordinator, bystander);
        let bystander_notify = coordinator.actor_registry.get(&bystander).unwrap().notify.clone();

        let target = mock_network_account_id_seeded(42);
        let note = mock_single_target_note(target, 10);
        let effects = CommittedBlockEffects {
            header: mock_block_header(1_u32.into()),
            network_notes: vec![note],
            nullifiers: vec![],
            network_account_updates: vec![],
        };

        coordinator.handle_committed_block(&effects);

        assert!(
            bystander_notify.notified().now_or_never().is_some(),
            "every registered actor should be notified on a committed block",
        );

        assert!(
            coordinator.actor_registry.contains_key(&target),
            "freshly-targeted account should get an actor",
        );
    }
}
