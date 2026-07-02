use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::account::AccountId;
use miden_standards::note::AccountTargetNetworkNote;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::LOG_TARGET;
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
/// Actors only operate on committed account state, so spawning is restricted to accounts whose
/// creation has been committed: a spawn requested for a not-yet-committed account is deferred
/// until the block carrying the account's creation arrives.
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

    /// Accounts targeted by network notes whose creation transaction has not been committed yet.
    ///
    /// Their actor spawn is deferred until a committed block carries the account's creation, at
    /// which point [`Coordinator::handle_committed_block`] promotes them to a real actor.
    pending_spawns: HashSet<AccountId>,
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
            pending_spawns: HashSet::new(),
        }
    }

    /// Spawns a new actor to manage the state of the provided network account.
    ///
    /// This method creates a new [`AccountActor`] instance for the specified account origin
    /// and adds it to the coordinator's management system. The actor will be responsible for
    /// processing transactions and managing state for the network account.
    #[miden_instrument(name = "ntx.builder.spawn_actor", skip(self))]
    pub fn spawn_actor(&mut self, account_id: AccountId) {
        if let Some(&count) = self.crash_counts.get(&account_id)
            && count >= self.max_account_crashes
        {
            tracing::warn!(
                target: LOG_TARGET,
                {
                    account.id = %account_id,
                    crash_count = count,
                },
                "Account deactivated due to repeated crashes, skipping actor spawn"
            );
            return;
        }

        if self.actor_registry.contains_key(&account_id) {
            tracing::error!(
                target: LOG_TARGET,
                { account.id = %account_id },
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
        tracing::debug!(
            target: LOG_TARGET,
            { account.id = %account_id },
            "Created actor for account"
        );
    }

    /// Spawns an actor for the given account if its committed state exists in the DB; otherwise
    /// defers the spawn until the block carrying the account's creation arrives.
    ///
    /// Actors only operate on committed account state, so spawning earlier would only produce an
    /// actor idling for the creation transaction to commit.
    pub async fn spawn_actor_when_committed(
        &mut self,
        account_id: AccountId,
    ) -> anyhow::Result<()> {
        if self.actor_registry.contains_key(&account_id) {
            return Ok(());
        }

        let committed = self
            .actor_context
            .state
            .db
            .account_exists(account_id)
            .await
            .context("failed to check for committed account state")?;

        if committed {
            self.spawn_actor(account_id);
        } else {
            tracing::info!(
                target: LOG_TARGET,
                { account.id = %account_id },
                "deferring actor spawn until the account's creation is committed",
            );
            self.pending_spawns.insert(account_id);
        }
        Ok(())
    }

    /// Reacts to a committed block: spawns actors for any newly-targeted network accounts whose
    /// committed state exists (deferring the rest until their creation commits), releases deferred
    /// spawns for accounts created by this block, and wakes every active actor so it can
    /// re-evaluate its state.
    pub async fn handle_committed_block(
        &mut self,
        effects: &CommittedBlockEffects,
    ) -> anyhow::Result<()> {
        // Accounts created by this block release any spawn deferred on their creation.
        for account_id in effects.created_network_accounts() {
            if self.pending_spawns.remove(&account_id) {
                self.spawn_actor(account_id);
            }
        }

        let targeted: HashSet<AccountId> = effects
            .network_notes
            .iter()
            .map(AccountTargetNetworkNote::target_account_id)
            .collect();
        for account_id in targeted {
            self.spawn_actor_when_committed(account_id).await?;
        }

        for handle in self.actor_registry.values() {
            handle.notify();
        }
        Ok(())
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
                    target: LOG_TARGET,
                    {
                        account.id = %account_id,
                        error = %format!("{err:#}"),
                    },
                    "Account actor crashed"
                );
                self.actor_registry.remove(&account_id);
                Ok(None)
            },
            Some(Err(err)) => {
                tracing::error!(target: LOG_TARGET, error = %err, "Actor task failed");
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

    /// Seeds a committed row for `account_id` so the coordinator's spawn check sees the account.
    async fn seed_committed_account(coordinator: &Coordinator, account_id: AccountId) {
        let db = coordinator.actor_context.state.db.clone();
        db.upsert_account_for_test(account_id, mock_account(account_id), mock_transaction_id(0))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handle_committed_block_spawns_for_committed_note_target() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let target_id = mock_network_account_id();
        seed_committed_account(&coordinator, target_id).await;

        let note = mock_single_target_note(target_id, 10);
        let effects = CommittedBlockEffects {
            header: mock_block_header(1_u32.into()),
            network_notes: vec![note],
            nullifiers: vec![],
            network_account_updates: vec![],
            account_transactions: vec![],
        };

        coordinator.handle_committed_block(&effects).await.unwrap();

        assert!(
            coordinator.actor_registry.contains_key(&target_id),
            "a committed account targeted by a note should get a fresh actor",
        );
    }

    #[tokio::test]
    async fn handle_committed_block_defers_spawn_until_account_creation_commits() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let (account, details) = mock_network_account_update();
        let account_id = account.id();

        // A note targets the account before its creation transaction has been committed.
        let note = mock_single_target_note(account_id, 10);
        let effects = CommittedBlockEffects {
            header: mock_block_header(1_u32.into()),
            network_notes: vec![note],
            nullifiers: vec![],
            network_account_updates: vec![],
            account_transactions: vec![],
        };
        coordinator.handle_committed_block(&effects).await.unwrap();

        assert!(
            !coordinator.actor_registry.contains_key(&account_id),
            "an account without committed state must not get an actor",
        );
        assert!(
            coordinator.pending_spawns.contains(&account_id),
            "the spawn must be deferred until the account's creation commits",
        );

        // The creation commits in a later block; the builder persists the block's effects to the DB
        // before handing them to the coordinator.
        let db = coordinator.actor_context.state.db.clone();
        db.upsert_account_for_test(account_id, account, mock_transaction_id(0))
            .await
            .unwrap();
        let effects = CommittedBlockEffects {
            header: mock_block_header(2_u32.into()),
            network_notes: vec![],
            nullifiers: vec![],
            network_account_updates: vec![(account_id, details)],
            account_transactions: vec![],
        };
        coordinator.handle_committed_block(&effects).await.unwrap();

        assert!(
            coordinator.actor_registry.contains_key(&account_id),
            "the block committing the account's creation must release the deferred spawn",
        );
        assert!(
            coordinator.pending_spawns.is_empty(),
            "a released spawn must leave the pending set",
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
                miden_protocol::account::AccountUpdateDetails::Private,
            )],
            account_transactions: vec![],
        };

        coordinator.handle_committed_block(&effects).await.unwrap();

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
        seed_committed_account(&coordinator, target).await;
        let note = mock_single_target_note(target, 10);
        let effects = CommittedBlockEffects {
            header: mock_block_header(1_u32.into()),
            network_notes: vec![note],
            nullifiers: vec![],
            network_account_updates: vec![],
            account_transactions: vec![],
        };

        coordinator.handle_committed_block(&effects).await.unwrap();

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
