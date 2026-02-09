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
use crate::actor::{AccountActorContext, AccountOrigin};
use crate::coordinator::Coordinator;
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
    /// Shared chain state updated by the event loop and read by actors.
    chain_state: Arc<RwLock<ChainState>>,
    /// Context shared with all account actors.
    actor_context: AccountActorContext,
    /// Stream of mempool events from the block producer.
    mempool_events: MempoolEventStream,
}

impl NetworkTransactionBuilder {
    pub(crate) fn new(
        config: NtxBuilderConfig,
        coordinator: Coordinator,
        store: StoreClient,
        chain_state: Arc<RwLock<ChainState>>,
        actor_context: AccountActorContext,
        mempool_events: MempoolEventStream,
    ) -> Self {
        Self {
            config,
            coordinator,
            store,
            chain_state,
            actor_context,
            mempool_events,
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

    /// Handles account IDs loaded from the store by spawning actors for them.
    #[tracing::instrument(name = "ntx.builder.handle_loaded_account", skip(self, account_id))]
    async fn handle_loaded_account(
        &mut self,
        account_id: NetworkAccountId,
    ) -> Result<(), anyhow::Error> {
        self.coordinator
            .spawn_actor(AccountOrigin::store(account_id), &self.actor_context)
            .await?;
        Ok(())
    }

    /// Handles mempool events by routing them to actors and spawning new actors as needed.
    #[tracing::instrument(name = "ntx.builder.handle_mempool_event", skip(self, event))]
    async fn handle_mempool_event(
        &mut self,
        event: Arc<MempoolEvent>,
    ) -> Result<(), anyhow::Error> {
        match event.as_ref() {
            MempoolEvent::TransactionAdded { account_delta, .. } => {
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
            MempoolEvent::BlockCommitted { header, txs } => {
                self.update_chain_tip(header.as_ref().clone()).await;
                self.coordinator.broadcast(event.clone()).await;

                // All transactions pertaining to predating events should now be available
                // through the store. So we can now drain them.
                for tx_id in txs {
                    self.coordinator.drain_predating_events(tx_id);
                }
                Ok(())
            },
            // Broadcast to all actors.
            MempoolEvent::TransactionsReverted(txs) => {
                self.coordinator.broadcast(event.clone()).await;

                // Reverted predating transactions need not be processed.
                for tx_id in txs {
                    self.coordinator.drain_predating_events(tx_id);
                }
                Ok(())
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
