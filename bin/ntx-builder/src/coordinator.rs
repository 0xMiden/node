use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;
use miden_standards::note::AccountTargetNetworkNote;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::actor::{AccountActor, AccountActorContext};
use crate::committed_block::CommittedBlockEffects;

// ACCOUNT VIEW
// ================================================================================================

/// Per-account state the coordinator pushes to an actor on every committed block.
///
/// Every field is cumulative, so an actor that wakes after several blocks reads the latest view and
/// answers entirely in memory: "did my submission land" (`last_committed_tx`), "has it expired"
/// (`chain_tip` vs the submission block), and "is there new work" (`notes_seen` vs a local cursor).
/// The view is intentionally bounded: a single latest-tx slot and a monotone counter, never a
/// growing list.
#[derive(Clone, Debug)]
pub(crate) struct AccountView {
    /// Chain tip as of the latest committed block. Advances every block, so the view always changes
    /// and every actor wakes (cheaply, in memory) once per block.
    pub chain_tip: BlockNumber,
    /// Latest transaction committed against this account, mirroring `accounts.last_tx_id`. An actor
    /// waiting on its submission compares this against its own transaction id to confirm landing.
    pub last_committed_tx: Option<TransactionId>,
    /// Monotone count of network notes seen targeting this account since the actor was spawned. A
    /// local cursor on the actor side answers "is there new work" without a DB query.
    pub notes_seen: u64,
}

// ACTOR HANDLE
// ================================================================================================

/// Handle to an account actor spawned by the coordinator.
struct ActorHandle {
    /// Sender half of the per-account [`AccountView`] watch channel. The coordinator updates the
    /// view on every committed block; the actor awaits changes on its receiver and re-evaluates its
    /// state from the pushed data rather than querying the DB.
    view_tx: watch::Sender<AccountView>,
}

impl ActorHandle {
    fn new(view_tx: watch::Sender<AccountView>) -> Self {
        Self { view_tx }
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
///    spawns missing actors for accounts that just received new network notes and pushes a fresh
///    [`AccountView`] to every active actor so it can re-evaluate its state in memory.
///
/// Actors only operate on committed account state, so spawning is restricted to accounts whose
/// creation has been committed: a spawn requested for a not-yet-committed account is deferred
/// until the block carrying the account's creation arrives.
///
/// State changes are pushed through a per-account [`watch`] channel: intermediate views are
/// coalesced (an actor busy for several blocks only ever sees the latest). Actors that crash
/// repeatedly are deactivated after `max_account_crashes` failures.
pub struct Coordinator {
    /// Mapping of network account IDs to their view-channel handles.
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

        let initial_view = AccountView {
            chain_tip: self.actor_context.state.chain.chain_tip_block_number(),
            last_committed_tx: None,
            notes_seen: 0,
        };
        let (view_tx, view_rx) = watch::channel(initial_view);
        let actor = AccountActor::new(account_id, &self.actor_context);
        let handle = ActorHandle::new(view_tx);

        let semaphore = self.semaphore.clone();
        self.actor_join_set
            .spawn(Box::pin(async move { (account_id, actor.run(semaphore, view_rx).await) }));

        self.actor_registry.insert(account_id, handle);
        tracing::info!(account.id = %account_id, "Created actor for account");
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
                account.id = %account_id,
                "deferring actor spawn until the account's creation is committed",
            );
            self.pending_spawns.insert(account_id);
        }
        Ok(())
    }

    /// Reacts to a committed block: spawns actors for any newly-targeted network accounts whose
    /// committed state exists (deferring the rest until their creation commits), releases deferred
    /// spawns for accounts created by this block, and pushes a fresh [`AccountView`] to every
    /// active actor so it can re-evaluate its state in memory.
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
        for account_id in &targeted {
            self.spawn_actor_when_committed(*account_id).await?;
        }

        // Push the block's effects to every active actor. The latest transaction per account is the
        // same map `apply_committed_block` uses for `accounts.last_tx_id`, so the pushed
        // `last_committed_tx` agrees with the persisted state; the per-account note counts feed the
        // `notes_seen` work counter.
        let chain_tip = effects.header.block_num();
        let latest_tx = effects.latest_tx_per_account();
        let mut new_notes: HashMap<AccountId, u64> = HashMap::new();
        for note in &effects.network_notes {
            *new_notes.entry(note.target_account_id()).or_default() += 1;
        }

        for (account_id, handle) in &self.actor_registry {
            let committed_tx = latest_tx.get(account_id).copied();
            let notes = new_notes.get(account_id).copied().unwrap_or(0);
            handle.view_tx.send_modify(|view| {
                view.chain_tip = chain_tip;
                if let Some(tx) = committed_tx {
                    view.last_committed_tx = Some(tx);
                }
                view.notes_seen += notes;
            });
        }
        Ok(())
    }

    /// Waits for the next actor to complete and handles the outcome.
    ///
    /// Returns `Some(account_id)` if an actor should be respawned (because work reappeared for the
    /// account between its last view observation and its idle shutdown), or `None` otherwise. If no
    /// actors are currently running, this method waits indefinitely until new actors are spawned.
    pub async fn next(&mut self) -> anyhow::Result<Option<AccountId>> {
        let actor_result = self.actor_join_set.join_next().await;
        match actor_result {
            Some(Ok((account_id, Ok(())))) => {
                // Actor shut down intentionally on idle timeout, which only happens when it had no
                // pending notes. Reap it, then respawn if a block committed between its last
                // observation and its exit added (or re-armed) work for the account: that view
                // update went to a now-dropped receiver and would otherwise wait for the next
                // block.
                self.actor_registry.remove(&account_id);
                let should_respawn = self.account_has_pending_notes(account_id).await?;
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

    /// Returns `true` if the account has any pending notes: eligible now, or awaiting a backoff or
    /// execution-hint window. Used to decide whether to respawn an actor that just idle-timed-out.
    async fn account_has_pending_notes(&self, account_id: AccountId) -> anyhow::Result<bool> {
        self.actor_context
            .state
            .db
            .account_has_pending_notes(account_id, self.actor_context.config.max_note_attempts)
            .await
            .context("failed to check pending notes when reaping an idle actor")
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
    use super::*;
    use crate::test_utils::*;

    /// Registers a dummy actor handle (no real actor task) in the coordinator's registry and
    /// returns the view receiver so the test can observe what the coordinator pushes.
    fn register_dummy_actor(
        coordinator: &mut Coordinator,
        account_id: AccountId,
    ) -> watch::Receiver<AccountView> {
        let (view_tx, view_rx) = watch::channel(AccountView {
            chain_tip: BlockNumber::GENESIS,
            last_committed_tx: None,
            notes_seen: 0,
        });
        coordinator.actor_registry.insert(account_id, ActorHandle::new(view_tx));
        view_rx
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
                miden_protocol::account::delta::AccountUpdateDetails::Private,
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
    async fn handle_committed_block_pushes_view_to_existing_actors() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let bystander = mock_network_account_id();
        let mut bystander_rx = register_dummy_actor(&mut coordinator, bystander);
        // Mark the initial view as seen so the post-block update is observable as a change.
        let _ = bystander_rx.borrow_and_update();

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
            bystander_rx.has_changed().unwrap(),
            "every registered actor should receive a view update on a committed block",
        );
        let view = bystander_rx.borrow_and_update();
        assert_eq!(view.chain_tip, 1_u32.into(), "the view carries the new chain tip");
        assert_eq!(view.notes_seen, 0, "a bystander targeted by no note sees no new work");
        drop(view);

        assert!(
            coordinator.actor_registry.contains_key(&target),
            "freshly-targeted account should get an actor",
        );
    }

    /// The pushed view carries the account's latest committed transaction (for landing detection)
    /// and a bumped note counter (for the work signal).
    #[tokio::test]
    async fn handle_committed_block_view_carries_landing_and_new_notes() {
        let (mut coordinator, _dir, _rx) = Coordinator::test().await;

        let account_id = mock_network_account_id();
        // A dummy handle for the targeted account so the coordinator updates it in place instead of
        // spawning a real actor (which would own the receiver and hide it from the test).
        let mut rx = register_dummy_actor(&mut coordinator, account_id);
        let _ = rx.borrow_and_update();

        let tx_id = mock_transaction_id(5);
        let note = mock_single_target_note(account_id, 10);
        let effects = CommittedBlockEffects {
            header: mock_block_header(3_u32.into()),
            network_notes: vec![note],
            nullifiers: vec![],
            network_account_updates: vec![],
            account_transactions: vec![(account_id, tx_id)],
        };

        coordinator.handle_committed_block(&effects).await.unwrap();

        let view = rx.borrow_and_update();
        assert_eq!(view.chain_tip, 3_u32.into());
        assert_eq!(
            view.last_committed_tx,
            Some(tx_id),
            "the account's latest committed tx is pushed for in-memory landing detection",
        );
        assert_eq!(view.notes_seen, 1, "one note targeting the account bumps the work counter");
    }
}
