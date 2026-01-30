use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Context;
use futures::TryStreamExt;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::PartialBlockchain;
use tokio::sync::{RwLock, mpsc};
use url::Url;

use crate::MAX_IN_PROGRESS_TXS;
use crate::actor::{AccountActorContext, AccountOrigin};
use crate::block_producer::BlockProducerClient;
use crate::coordinator::Coordinator;
use crate::store::StoreClient;

// CONSTANTS
// =================================================================================================

/// The maximum number of blocks to keep in memory while tracking the chain tip.
const MAX_BLOCK_COUNT: usize = 4;

// CHAIN STATE
// ================================================================================================

/// Contains information about the chain that is relevant to the [`NetworkTransactionProducer`] and
/// all account actors managed by the [`Coordinator`]
#[derive(Debug, Clone)]
pub struct ChainState {
    /// The current tip of the chain.
    pub chain_tip_header: BlockHeader,
    /// A partial representation of the latest state of the chain.
    pub chain_mmr: PartialBlockchain,
}

impl ChainState {
    /// Constructs a new instance of [`ChainState`].
    fn new(chain_tip_header: BlockHeader, chain_mmr: PartialMmr) -> Self {
        let chain_mmr = PartialBlockchain::new(chain_mmr, [])
            .expect("partial blockchain should build from partial mmr");
        Self { chain_tip_header, chain_mmr }
    }

    /// Consumes the chain state and returns the chain tip header and the partial blockchain as a
    /// tuple.
    pub fn into_parts(self) -> (BlockHeader, PartialBlockchain) {
        (self.chain_tip_header, self.chain_mmr)
    }
}

// NETWORK TRANSACTION PRODUCER
// ================================================================================================

/// Network transaction producer component.
///
/// The network transaction producer is in charge of producing transactions that consume notes
/// against network accounts. These notes are identified and communicated by the block producer.
/// The service maintains a list of unconsumed notes and periodically executes and proves
/// transactions that consume them (reaching out to the store to retrieve state as necessary).
///
/// The producer manages the tasks for every network account on the chain through the coordinator.
pub struct NetworkTransactionProducer {
    /// Address of the store gRPC server.
    store_url: Url,
    /// Address of the block producer gRPC server.
    block_producer_url: Url,
    /// Address of the Validator server.
    validator_url: Url,
    /// Address of the remote prover. If `None`, transactions will be proven locally, which is
    /// undesirable due to the performance impact.
    tx_prover_url: Option<Url>,
    /// Shared LRU cache for storing retrieved note scripts to avoid repeated store calls.
    /// This cache is shared across all account actors.
    script_cache: LruCache<Word, NoteScript>,
    /// Coordinator for managing actor tasks.
    coordinator: Coordinator,
}

impl NetworkTransactionProducer {
    /// Channel capacity for account loading.
    const ACCOUNT_CHANNEL_CAPACITY: usize = 1_000;

    /// Creates a new instance of the network transaction producer.
    pub fn new(
        store_url: Url,
        block_producer_url: Url,
        validator_url: Url,
        tx_prover_url: Option<Url>,
        script_cache_size: NonZeroUsize,
    ) -> Self {
        let script_cache = LruCache::new(script_cache_size);
        let coordinator = Coordinator::new(MAX_IN_PROGRESS_TXS);
        Self {
            store_url,
            block_producer_url,
            validator_url,
            tx_prover_url,
            script_cache,
            coordinator,
        }
    }

    /// Runs the network transaction producer until a fatal error occurs.
    pub async fn run(mut self) -> anyhow::Result<()> {
        let store = StoreClient::new(self.store_url.clone());
        let block_producer = BlockProducerClient::new(self.block_producer_url.clone());

        // Loop until we successfully subscribe.
        //
        // The mempool rejects our subscription if we don't have the same view of the chain aka
        // if our chain tip does not match the mempools. This can occur if a new block is committed
        // _after_ we fetch the chain tip from the store but _before_ our subscription request is
        // handled.
        //
        // This is a hack-around for https://github.com/0xMiden/miden-node/issues/1566.
        let (chain_tip_header, chain_mmr, mut mempool_events) = loop {
            let (chain_tip_header, chain_mmr) = store
                .get_latest_blockchain_data_with_retry()
                .await?
                .expect("store should contain a latest block");

            match block_producer
                .subscribe_to_mempool_with_retry(chain_tip_header.block_num())
                .await
            {
                Ok(subscription) => break (chain_tip_header, chain_mmr, subscription),
                Err(status) if status.code() == tonic::Code::InvalidArgument => {
                    tracing::error!(err=%status, "mempool subscription failed due to desync, trying again");
                },
                Err(err) => return Err(err).context("failed to subscribe to mempool events"),
            }
        };

        // Create chain state that will be updated by the coordinator and read by actors.
        let chain_state = Arc::new(RwLock::new(ChainState::new(chain_tip_header, chain_mmr)));

        let actor_context = AccountActorContext {
            block_producer_url: self.block_producer_url.clone(),
            validator_url: self.validator_url.clone(),
            tx_prover_url: self.tx_prover_url.clone(),
            chain_state: chain_state.clone(),
            store: store.clone(),
            script_cache: self.script_cache.clone(),
        };

        // Spawn a background task to load network accounts from the store.
        // Accounts are sent through a channel in batches and processed in the main event loop.
        let (account_tx, mut account_rx) =
            mpsc::channel::<NetworkAccountId>(Self::ACCOUNT_CHANNEL_CAPACITY);
        let account_loader_store = store.clone();
        let mut account_loader_handle = tokio::spawn(async move {
            account_loader_store
                .stream_network_account_ids(account_tx)
                .await
                .context("failed to load network accounts from store")
        });

        // Main loop which manages actors and passes mempool events to them.
        loop {
            tokio::select! {
                // Handle actor result.
                result = self.coordinator.next() => {
                    result?;
                },
                // Handle mempool events.
                event = mempool_events.try_next() => {
                    let event = event
                        .context("mempool event stream ended")?
                        .context("mempool event stream failed")?;

                    self.handle_mempool_event(
                        event.into(),
                        &actor_context,
                        chain_state.clone(),
                    ).await?;
                },
                // Handle account batches loaded from the store.
                // Once all accounts are loaded, the channel closes and this branch
                // becomes inactive (recv returns None and we stop matching).
                Some(account_id) = account_rx.recv() => {
                    self.handle_loaded_account(account_id, &actor_context).await?;
                },
                // Handle account loader task completion/failure.
                // If the task fails, we abort since the producer would be in a degraded state
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

    /// Handles a batch of account IDs loaded from the store by spawning actors for them.
    #[tracing::instrument(
        name = "ntx.producer.handle_loaded_accounts",
        skip(self, account_id, actor_context)
    )]
    async fn handle_loaded_account(
        &mut self,
        account_id: NetworkAccountId,
        actor_context: &AccountActorContext,
    ) -> Result<(), anyhow::Error> {
        self.coordinator
            .spawn_actor(AccountOrigin::store(account_id), actor_context)
            .await?;
        Ok(())
    }

    /// Handles mempool events by sending them to actors via the coordinator and/or spawning new
    /// actors as required.
    #[tracing::instrument(
        name = "ntx.producer.handle_mempool_event",
        skip(self, event, actor_context, chain_state)
    )]
    async fn handle_mempool_event(
        &mut self,
        event: Arc<MempoolEvent>,
        actor_context: &AccountActorContext,
        chain_state: Arc<RwLock<ChainState>>,
    ) -> Result<(), anyhow::Error> {
        match event.as_ref() {
            MempoolEvent::TransactionAdded { account_delta, .. } => {
                // Handle account deltas in case an account is being created.
                if let Some(AccountUpdateDetails::Delta(delta)) = account_delta {
                    // Handle account deltas for network accounts only.
                    if let Some(network_account) = AccountOrigin::transaction(delta) {
                        // Spawn new actors if a transaction creates a new network account
                        let is_creating_account = delta.is_full_state();
                        if is_creating_account {
                            self.coordinator.spawn_actor(network_account, actor_context).await?;
                        }
                    }
                }
                self.coordinator.send_targeted(&event).await?;
                Ok(())
            },
            // Update chain state and broadcast.
            MempoolEvent::BlockCommitted { header, txs } => {
                self.update_chain_tip(header.as_ref().clone(), chain_state).await;
                self.coordinator.broadcast(event.clone()).await;

                // All transactions pertaining to predating events should now be available through
                // the store. So we can now drain them.
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

    /// Updates the chain tip and MMR block count.
    ///
    /// Blocks in the MMR are pruned if the block count exceeds the maximum.
    async fn update_chain_tip(&mut self, tip: BlockHeader, chain_state: Arc<RwLock<ChainState>>) {
        // Lock the chain state.
        let mut chain_state = chain_state.write().await;

        // Update MMR which lags by one block.
        let mmr_tip = chain_state.chain_tip_header.clone();
        chain_state.chain_mmr.add_block(&mmr_tip, true);

        // Set the new tip.
        chain_state.chain_tip_header = tip;

        // Keep MMR pruned.
        let pruned_block_height =
            (chain_state.chain_mmr.chain_length().as_usize().saturating_sub(MAX_BLOCK_COUNT))
                as u32;
        chain_state.chain_mmr.prune_to(..pruned_block_height.into());
    }
}
