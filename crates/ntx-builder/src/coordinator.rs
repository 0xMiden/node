use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use indexmap::IndexMap;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_proto::domain::note::NetworkNote;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::transaction::TransactionId;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::actor::{AccountActor, AccountActorContext, AccountOrigin, ActorShutdownReason};

// ACTOR HANDLE
// ================================================================================================

/// Handle to account actors that are spawned by the coordinator.
#[derive(Clone)]
struct ActorHandle {
    event_tx: mpsc::Sender<Arc<MempoolEvent>>,
    cancel_token: CancellationToken,
}

impl ActorHandle {
    fn new(event_tx: mpsc::Sender<Arc<MempoolEvent>>, cancel_token: CancellationToken) -> Self {
        Self { event_tx, cancel_token }
    }
}

// COORDINATOR
// ================================================================================================

/// Coordinator for managing [`AccountActor`] instances, tasks, and associated communication.
///
/// The `Coordinator` is the central orchestrator of the network transaction builder system.
/// It manages the lifecycle of account actors. Each actor is responsible for handling transactions
/// for a specific network account. The coordinator provides the following core
/// functionality:
///
/// ## Actor Management
/// - Spawns new [`AccountActor`] instances for network accounts as needed.
/// - Maintains a registry of active actors with their communication channels.
/// - Gracefully handles actor shutdown and cleanup when actors complete or fail.
/// - Monitors actor tasks through a join set to detect completion or errors.
///
/// ## Event Broadcasting
/// - Distributes mempool events to all account actors.
/// - Handles communication failures by canceling disconnected actors.
/// - Maintains reliable message delivery through dedicated channels per actor.
///
/// ## Resource Management
/// - Controls transaction concurrency across all network accounts using a semaphore.
/// - Prevents resource exhaustion by limiting simultaneous transaction processing.
///
/// The coordinator operates in an event-driven manner:
/// 1. Network accounts are registered and actors spawned as needed.
/// 2. Mempool events are broadcast to all active actors.
/// 3. Actor completion/failure events are monitored and handled.
/// 4. Failed or completed actors are cleaned up from the registry.
pub struct Coordinator {
    /// Mapping of network account IDs to their respective message channels and cancellation
    /// tokens.
    ///
    /// This registry serves as the primary directory for communicating with active account actors.
    /// When actors are spawned, they register their communication channel here. When events need
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

    /// Cache of events received from the mempool that predate corresponding network accounts.
    /// Grouped by network account ID to allow targeted event delivery to actors upon creation.
    predating_events: HashMap<NetworkAccountId, IndexMap<TransactionId, Arc<MempoolEvent>>>,

    /// Channel size for each actor's event channel.
    actor_channel_size: usize,
}

impl Coordinator {
    /// Creates a new coordinator with the specified maximum number of inflight transactions
    /// and actor channel size.
    pub fn new(max_inflight_transactions: usize, actor_channel_size: usize) -> Self {
        Self {
            actor_registry: HashMap::new(),
            actor_join_set: JoinSet::new(),
            semaphore: Arc::new(Semaphore::new(max_inflight_transactions)),
            predating_events: HashMap::new(),
            actor_channel_size,
        }
    }

    /// Spawns a new actor to manage the state of the provided network account.
    ///
    /// This method creates a new [`AccountActor`] instance for the specified account origin
    /// and adds it to the coordinator's management system. The actor will be responsible for
    /// processing transactions and managing state for the network account.
    #[tracing::instrument(name = "ntx.builder.spawn_actor", skip(self, origin, actor_context))]
    pub async fn spawn_actor(
        &mut self,
        origin: AccountOrigin,
        actor_context: &AccountActorContext,
    ) -> Result<(), SendError<Arc<MempoolEvent>>> {
        let account_id = origin.id();

        // If an actor already exists for this account ID, something has gone wrong.
        if let Some(handle) = self.actor_registry.remove(&account_id) {
            tracing::error!("account actor already exists for account: {}", account_id);
            handle.cancel_token.cancel();
        }

        let (event_tx, event_rx) = mpsc::channel(self.actor_channel_size);
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let actor = AccountActor::new(origin, actor_context, event_rx, cancel_token.clone());
        let handle = ActorHandle::new(event_tx, cancel_token);

        // Run the actor.
        let semaphore = self.semaphore.clone();
        self.actor_join_set.spawn(Box::pin(actor.run(semaphore)));

        // Send the new actor any events that contain notes that predate account creation.
        if let Some(predating_events) = self.predating_events.remove(&account_id) {
            for event in predating_events.values() {
                Self::send(&handle, event.clone()).await?;
            }
        }

        self.actor_registry.insert(account_id, handle);
        tracing::info!("created actor for account: {}", account_id);
        Ok(())
    }

    /// Broadcasts a mempool event to all active account actors.
    ///
    /// This method distributes the provided event to every actor currently registered
    /// with the coordinator. Each actor will receive the event through its dedicated
    /// message channel and can process it accordingly.
    ///
    /// If an actor fails to receive the event, it will be canceled.
    pub async fn broadcast(&mut self, event: Arc<MempoolEvent>) {
        tracing::debug!(
            actor_count = self.actor_registry.len(),
            "broadcasting event to all actors"
        );

        let mut failed_actors = Vec::new();

        // Send event to all actors.
        for (account_id, handle) in &self.actor_registry {
            if let Err(err) = Self::send(handle, event.clone()).await {
                tracing::error!("failed to send event to actor {}: {}", account_id, err);
                failed_actors.push(*account_id);
            }
        }
        // Remove failed actors from registry and cancel them.
        for account_id in failed_actors {
            let handle =
                self.actor_registry.remove(&account_id).expect("actor found in send loop above");
            handle.cancel_token.cancel();
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
                    tracing::info!("account actor cancelled: {}", account_id);
                    Ok(())
                },
                ActorShutdownReason::AccountReverted(account_id) => {
                    tracing::info!("account reverted: {}", account_id);
                    self.actor_registry.remove(&account_id);
                    Ok(())
                },
                ActorShutdownReason::EventChannelClosed => {
                    anyhow::bail!("event channel closed");
                },
                ActorShutdownReason::SemaphoreFailed(err) => Err(err).context("semaphore failed"),
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

    /// Sends a mempool event to all network account actors that are found in the corresponding
    /// transaction's notes.
    ///
    /// Caches the mempool event for each network account found in the transaction's notes that does
    /// not currently have a corresponding actor. If an actor does not exist for the account, it is
    /// assumed that the account has not been created on the chain yet.
    ///
    /// Cached events will be fed to the corresponding actor when the account creation transaction
    /// is processed.
    pub async fn send_targeted(
        &mut self,
        event: &Arc<MempoolEvent>,
    ) -> Result<(), SendError<Arc<MempoolEvent>>> {
        let mut target_actors = HashMap::new();
        if let MempoolEvent::TransactionAdded { id, network_notes, account_delta, .. } =
            event.as_ref()
        {
            // We need to inform the account if it was updated. This lets it know that its own
            // transaction has been applied, and in the future also resolves race conditions with
            // external network transactions (once these are allowed).
            if let Some(AccountUpdateDetails::Delta(delta)) = account_delta {
                let account_id = delta.id();
                if account_id.is_network() {
                    let network_account_id =
                        account_id.try_into().expect("account is network account");
                    if let Some(actor) = self.actor_registry.get(&network_account_id) {
                        target_actors.insert(network_account_id, actor);
                    }
                }
            }

            // Determine target actors for each note.
            for note in network_notes {
                let NetworkNote::SingleTarget(note) = note;
                let network_account_id = note.account_id();
                if let Some(actor) = self.actor_registry.get(&network_account_id) {
                    // Register actor as target.
                    target_actors.insert(network_account_id, actor);
                } else {
                    // Cache event for every note that doesn't have a corresponding actor.
                    self.predating_events
                        .entry(network_account_id)
                        .or_default()
                        .insert(*id, event.clone());
                }
            }
        }
        // Send event to target actors.
        for actor in target_actors.values() {
            Self::send(actor, event.clone()).await?;
        }
        Ok(())
    }

    /// Removes any cached events for a given transaction ID from all account caches.
    pub fn drain_predating_events(&mut self, tx_id: &TransactionId) {
        // Remove the transaction from all account caches.
        // This iterates over all predating events which is fine because the count is expected to be
        // low.
        self.predating_events.retain(|_, account_events| {
            account_events.shift_remove(tx_id);
            // Remove entries for accounts with no more cached events.
            !account_events.is_empty()
        });
    }

    /// Helper function to send an event to a single account actor.
    async fn send(
        handle: &ActorHandle,
        event: Arc<MempoolEvent>,
    ) -> Result<(), SendError<Arc<MempoolEvent>>> {
        handle.event_tx.send(event).await
    }
}
