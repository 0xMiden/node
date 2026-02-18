use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use futures::Stream;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::transaction::PartialBlockchain;
use tokio::sync::{RwLock, mpsc};
use tokio_stream::StreamExt;
use tonic::Status;

use crate::NtxBuilderConfig;
use crate::actor::{AccountActorContext, AccountOrigin, ActorNotification};
use crate::coordinator::Coordinator;
use crate::db::Db;
use crate::store::StoreClient;

// CHAIN STATE
// ================================================================================================

/// Contains information about the chain that is relevant to the [`NetworkTransactionBuilder`] and
/// all account actors managed by the [`Coordinator`].
///
/// The chain MMR stored here contains:
/// - The MMR peaks.
/// - Block headers and authentication paths for the last [`NtxBuilderConfig::max_block_count`]
///   blocks.
///
/// Authentication paths for older blocks are pruned because the NTX builder executes all notes as
/// "unauthenticated" (see [`InputNotes::from_unauthenticated_notes`]) and therefore does not need
/// to prove that input notes were created in specific past blocks.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// The current tip of the chain.
    pub chain_tip_header: BlockHeader,
    /// A partial representation of the chain MMR.
    ///
    /// Contains block headers and authentication paths for the last
    /// [`NtxBuilderConfig::max_block_count`] blocks only, since all notes are executed as
    /// unauthenticated.
    pub chain_mmr: Arc<PartialBlockchain>,
}

impl ChainState {
    /// Constructs a new instance of [`ChainState`].
    pub(crate) fn new(chain_tip_header: BlockHeader, chain_mmr: PartialMmr) -> Self {
        let chain_mmr = PartialBlockchain::new(chain_mmr, [])
            .expect("partial blockchain should build from partial mmr");
        Self {
            chain_tip_header,
            chain_mmr: Arc::new(chain_mmr),
        }
    }

    /// Consumes the chain state and returns the chain tip header and the partial blockchain as a
    /// tuple.
    pub fn into_parts(self) -> (BlockHeader, Arc<PartialBlockchain>) {
        (self.chain_tip_header, self.chain_mmr)
    }
}

// NETWORK TRANSACTION BUILDER
// ================================================================================================

/// A boxed, pinned stream of mempool events with a `'static` lifetime.
///
/// Boxing gives the stream a `'static` lifetime by ensuring it owns all its data, avoiding
/// complex lifetime annotations that would otherwise be required when storing `impl TryStream`.
pub(crate) type MempoolEventStream =
    Pin<Box<dyn Stream<Item = Result<MempoolEvent, Status>> + Send>>;

/// Network transaction builder component.
///
/// The network transaction builder is in charge of building transactions that consume notes
/// against network accounts. These notes are identified and communicated by the block producer.
/// The service maintains a list of unconsumed notes and periodically executes and proves
/// transactions that consume them (reaching out to the store to retrieve state as necessary).
///
/// The builder manages the tasks for every network account on the chain through the coordinator.
///
/// Create an instance using [`NtxBuilderConfig::build()`].
pub struct NetworkTransactionBuilder {
    /// Configuration for the builder.
    config: NtxBuilderConfig,
    /// Coordinator for managing actor tasks.
    coordinator: Coordinator,
    /// Client for the store gRPC API.
    store: StoreClient,
    /// Database for persistent state.
    db: Db,
    /// Shared chain state updated by the event loop and read by actors.
    chain_state: Arc<RwLock<ChainState>>,
    /// Context shared with all account actors.
    actor_context: AccountActorContext,
    /// Stream of mempool events from the block producer.
    mempool_events: MempoolEventStream,
    /// Receiver for notifications from account actors (e.g., note failures).
    notification_rx: mpsc::UnboundedReceiver<ActorNotification>,
}

impl NetworkTransactionBuilder {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: NtxBuilderConfig,
        coordinator: Coordinator,
        store: StoreClient,
        db: Db,
        chain_state: Arc<RwLock<ChainState>>,
        actor_context: AccountActorContext,
        mempool_events: MempoolEventStream,
        notification_rx: mpsc::UnboundedReceiver<ActorNotification>,
    ) -> Self {
        Self {
            config,
            coordinator,
            store,
            db,
            chain_state,
            actor_context,
            mempool_events,
            notification_rx,
        }
    }

    /// Runs the network transaction builder event loop until a fatal error occurs.
    ///
    /// This method:
    /// 1. Spawns a background task to load existing network accounts from the store
    /// 2. Runs the main event loop, processing mempool events and managing actors
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The mempool event stream ends unexpectedly
    /// - An actor encounters a fatal error
    /// - The account loader task fails
    pub async fn run(mut self) -> anyhow::Result<()> {
        // Spawn a background task to load network accounts from the store.
        // Accounts are sent through a channel and processed in the main event loop.
        let (account_tx, mut account_rx) =
            mpsc::channel::<NetworkAccountId>(self.config.account_channel_capacity);
        let account_loader_store = self.store.clone();
        let mut account_loader_handle = tokio::spawn(async move {
            account_loader_store
                .stream_network_account_ids(account_tx)
                .await
                .context("failed to load network accounts from store")
        });

        // Main event loop.
        loop {
            tokio::select! {
                // Handle actor result.
                result = self.coordinator.next() => {
                    result?;
                },
                // Handle mempool events.
                event = self.mempool_events.next() => {
                    let event = event
                        .context("mempool event stream ended")?
                        .context("mempool event stream failed")?;

                    self.handle_mempool_event(event.into()).await?;
                },
                // Handle account batches loaded from the store.
                // Once all accounts are loaded, the channel closes and this branch
                // becomes inactive (recv returns None and we stop matching).
                Some(account_id) = account_rx.recv() => {
                    self.handle_loaded_account(account_id).await?;
                },
                // Handle actor notifications (DB writes delegated from actors).
                Some(notification) = self.notification_rx.recv() => {
                    self.handle_actor_notification(notification).await;
                },
                // Handle account loader task completion/failure.
                // If the task fails, we abort since the builder would be in a degraded state
                // where existing notes against network accounts won't be processed.
                result = &mut account_loader_handle => {
                    result
                        .context("account loader task panicked")
                        .flatten()?;

                    tracing::info!("account loading from store completed");
                    account_loader_handle = tokio::spawn(std::future::pending());
                },
            }
        }
    }

    /// Handles account IDs loaded from the store by syncing state to DB and spawning actors.
    #[tracing::instrument(name = "ntx.builder.handle_loaded_account", skip(self, account_id))]
    async fn handle_loaded_account(
        &mut self,
        account_id: NetworkAccountId,
    ) -> Result<(), anyhow::Error> {
        // Fetch account from store and write to DB.
        let account = self
            .store
            .get_network_account(account_id)
            .await
            .context("failed to load account from store")?
            .context("account should exist in store")?;

        let block_num = self.chain_state.read().await.chain_tip_header.block_num();
        let notes = self
            .store
            .get_unconsumed_network_notes(account_id, block_num.as_u32())
            .await
            .context("failed to load notes from store")?;

        let notes: Vec<_> = notes
            .into_iter()
            .map(|n| {
                let miden_node_proto::domain::note::NetworkNote::SingleTarget(note) = n;
                note
            })
            .collect();

        // Write account and notes to DB.
        self.db
            .sync_account_from_store(account_id, account.clone(), notes.clone())
            .await
            .context("failed to sync account to DB")?;

        self.coordinator
            .spawn_actor(AccountOrigin::store(account_id), &self.actor_context)
            .await?;
        Ok(())
    }

    /// Handles mempool events by writing to DB first, then routing to actors.
    #[tracing::instrument(name = "ntx.builder.handle_mempool_event", skip(self, event))]
    async fn handle_mempool_event(
        &mut self,
        event: Arc<MempoolEvent>,
    ) -> Result<(), anyhow::Error> {
        match event.as_ref() {
            MempoolEvent::TransactionAdded { account_delta, .. } => {
                // Write event effects to DB first.
                self.coordinator
                    .write_event(&event)
                    .await
                    .context("failed to write TransactionAdded to DB")?;

                // Handle account deltas in case an account is being created.
                if let Some(AccountUpdateDetails::Delta(delta)) = account_delta {
                    // Handle account deltas for network accounts only.
                    if let Some(network_account) = AccountOrigin::transaction(delta) {
                        // Spawn new actors if a transaction creates a new network account.
                        let is_creating_account = delta.is_full_state();
                        if is_creating_account {
                            self.coordinator
                                .spawn_actor(network_account, &self.actor_context)
                                .await?;
                        }
                    }
                }
                self.coordinator.send_targeted(&event).await?;
                Ok(())
            },
            // Update chain state and broadcast.
            MempoolEvent::BlockCommitted { header, .. } => {
                // Write event effects to DB first.
                self.coordinator
                    .write_event(&event)
                    .await
                    .context("failed to write BlockCommitted to DB")?;

                self.update_chain_tip(header.as_ref().clone()).await;
                self.coordinator.broadcast(event.clone()).await;
                Ok(())
            },
            // Broadcast to all actors.
            MempoolEvent::TransactionsReverted(_) => {
                // Write event effects to DB first; returns reverted account IDs.
                let reverted_accounts = self
                    .coordinator
                    .write_event(&event)
                    .await
                    .context("failed to write TransactionsReverted to DB")?;

                self.coordinator.broadcast(event.clone()).await;

                // Cancel actors for reverted account creations.
                for account_id in &reverted_accounts {
                    self.coordinator.cancel_actor(account_id);
                }
                Ok(())
            },
        }
    }

    /// Processes a notification from an account actor by performing the corresponding DB write.
    async fn handle_actor_notification(&mut self, notification: ActorNotification) {
        match notification {
            ActorNotification::NotesFailed { nullifiers, block_num } => {
                if let Err(err) = self.db.notes_failed(nullifiers, block_num).await {
                    tracing::error!(err = %err, "failed to mark notes as failed");
                }
            },
            ActorNotification::DropFailingNotes { account_id, max_attempts } => {
                if let Err(err) = self.db.drop_failing_notes(account_id, max_attempts).await {
                    tracing::error!(err = %err, "failed to drop failing notes");
                }
            },
        }
    }

    /// Updates the chain tip and prunes old blocks from the MMR.
    async fn update_chain_tip(&mut self, tip: BlockHeader) {
        let mut chain_state = self.chain_state.write().await;

        // Update MMR which lags by one block.
        let mmr_tip = chain_state.chain_tip_header.clone();
        Arc::make_mut(&mut chain_state.chain_mmr).add_block(&mmr_tip, true);

        // Set the new tip.
        chain_state.chain_tip_header = tip;

        // Keep MMR pruned.
        let pruned_block_height = (chain_state
            .chain_mmr
            .chain_length()
            .as_usize()
            .saturating_sub(self.config.max_block_count)) as u32;
        Arc::make_mut(&mut chain_state.chain_mmr).prune_to(..pruned_block_height.into());
    }
}
