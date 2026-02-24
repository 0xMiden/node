use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_proto::domain::note::{NetworkNote, SingleTargetNetworkNote};
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::BlockNumber;
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
/// - Actors that have been idle for longer than the sterility timeout request shutdown from the
///   coordinator.
/// - The coordinator validates shutdown requests against the DB: if notes are still available for
///   the account, the request is rejected and the actor resumes processing.
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
}

impl Coordinator {
    /// Creates a new coordinator with the specified maximum number of inflight transactions.
    pub fn new(max_inflight_transactions: usize, db: Db) -> Self {
        Self {
            actor_registry: HashMap::new(),
            actor_join_set: JoinSet::new(),
            semaphore: Arc::new(Semaphore::new(max_inflight_transactions)),
            db,
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
    pub async fn next(&mut self) -> anyhow::Result<()> {
        let actor_result = self.actor_join_set.join_next().await;
        match actor_result {
            Some(Ok(shutdown_reason)) => match shutdown_reason {
                ActorShutdownReason::Cancelled(account_id) => {
                    // Do not remove the actor from the registry, as it may be re-spawned.
                    // The coordinator should always remove actors immediately after cancellation.
                    tracing::info!(account_id = %account_id, "Account actor cancelled");
                    Ok(())
                },
                ActorShutdownReason::SemaphoreFailed(err) => Err(err).context("semaphore failed"),
                ActorShutdownReason::DbError(account_id) => {
                    tracing::error!(account_id = %account_id, "Account actor shut down due to DB error");
                    Ok(())
                },
                ActorShutdownReason::Sterile(account_id) => {
                    tracing::info!(account_id = %account_id, "Account actor shut down due to sterility");
                    Ok(())
                },
            },
            Some(Err(err)) => {
                tracing::error!(err = %err, "actor task failed");
                Ok(())
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

    /// Handles a shutdown request from an actor that has been idle for longer than the sterility
    /// timeout.
    ///
    /// Validates the request by checking the DB for available notes. If notes are available, the
    /// shutdown is rejected by dropping `ack_tx` (the actor detects the `RecvError` and resumes).
    /// If no notes are available, the actor is deregistered and the ack is sent, allowing the
    /// actor to exit gracefully.
    pub async fn handle_shutdown_request(
        &mut self,
        account_id: NetworkAccountId,
        block_num: BlockNumber,
        max_note_attempts: usize,
        ack_tx: tokio::sync::oneshot::Sender<()>,
    ) {
        let has_notes = self
            .db
            .has_available_notes(account_id, block_num, max_note_attempts)
            .await
            .unwrap_or(false);

        if has_notes {
            // Reject: drop ack_tx -> actor detects RecvError, resumes.
            tracing::debug!(
                %account_id,
                "Rejected actor shutdown: notes available in DB"
            );
        } else {
            self.actor_registry.remove(&account_id);
            let _ = ack_tx.send(());
        }
    }

    /// Cancels an actor by its account ID.
    pub fn cancel_actor(&mut self, account_id: &NetworkAccountId) {
        if let Some(handle) = self.actor_registry.remove(account_id) {
            handle.cancel_token.cancel();
        }
    }

    /// Returns `true` if an actor is registered for the given account ID.
    #[cfg(test)]
    pub fn has_actor(&self, account_id: &NetworkAccountId) -> bool {
        self.actor_registry.contains_key(account_id)
    }
}

#[cfg(test)]
mod tests {
    use miden_node_proto::domain::mempool::MempoolEvent;
    use miden_node_proto::domain::note::NetworkNote;
    use miden_protocol::block::BlockNumber;

    use super::*;
    use crate::db::Db;
    use crate::test_utils::*;

    /// Creates a coordinator with default settings backed by a temp DB.
    async fn test_coordinator() -> (Coordinator, tempfile::TempDir) {
        let (db, dir) = Db::test_setup().await;
        (Coordinator::new(4, db), dir)
    }

    /// Registers a dummy actor handle (no real actor task) in the coordinator's registry.
    fn register_dummy_actor(coordinator: &mut Coordinator, account_id: NetworkAccountId) {
        let notify = Arc::new(Notify::new());
        let cancel_token = CancellationToken::new();
        coordinator
            .actor_registry
            .insert(account_id, ActorHandle::new(notify, cancel_token));
    }

    // HANDLE SHUTDOWN REQUEST TESTS
    // ============================================================================================

    #[tokio::test]
    async fn shutdown_approved_when_no_notes() {
        let (mut coordinator, _dir) = test_coordinator().await;
        let account_id = mock_network_account_id();

        register_dummy_actor(&mut coordinator, account_id);
        assert!(coordinator.has_actor(&account_id));

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let block_num = BlockNumber::from(1u32);
        let max_note_attempts = 30;

        coordinator
            .handle_shutdown_request(account_id, block_num, max_note_attempts, ack_tx)
            .await;

        // Ack should be received (shutdown approved).
        assert!(ack_rx.await.is_ok());
        // Actor should be deregistered.
        assert!(!coordinator.has_actor(&account_id));
    }

    #[tokio::test]
    async fn shutdown_rejected_when_notes_available() {
        let (mut coordinator, _dir) = test_coordinator().await;
        let account_id = mock_network_account_id();

        // Insert a committed note for this account.
        let note = mock_single_target_note(account_id, 10);
        coordinator
            .db
            .sync_account_from_store(account_id, mock_account(account_id), vec![note])
            .await
            .unwrap();

        register_dummy_actor(&mut coordinator, account_id);
        assert!(coordinator.has_actor(&account_id));

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let block_num = BlockNumber::from(1u32);
        let max_note_attempts = 30;

        coordinator
            .handle_shutdown_request(account_id, block_num, max_note_attempts, ack_tx)
            .await;

        // Ack_tx should have been dropped (shutdown rejected).
        assert!(ack_rx.await.is_err());
        // Actor should still be registered.
        assert!(coordinator.has_actor(&account_id));
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
}
