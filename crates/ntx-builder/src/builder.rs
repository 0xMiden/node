use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use futures::Stream;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::BlockNumber;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::NtxBuilderConfig;
use crate::actor::{AccountActorContext, AccountOrigin, ActorRequest};
use crate::chain_state::SharedChainState;
use crate::clients::StoreClient;
use crate::coordinator::Coordinator;
use crate::db::Db;
use crate::server::NtxBuilderRpcServer;

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
    chain_state: Arc<SharedChainState>,
    /// Context shared with all account actors.
    actor_context: AccountActorContext,
    /// Stream of mempool events from the block producer.
    mempool_events: MempoolEventStream,
    /// Database update requests from account actors.
    ///
    /// We keep database writes centralized so this is how actors communicate
    /// items to write.
    actor_request_rx: mpsc::Receiver<ActorRequest>,
    /// Inputs for the startup catch-up phase. Consumed once at the start of `run_event_loop`
    /// before the main loop opens.
    catch_up: CatchUpInputs,
}

/// Inputs that drive the ntx-builder's startup catch-up.
pub(crate) struct CatchUpInputs {
    /// First block whose state hasn't yet been ingested from the store. The lower bound of the
    /// range startup catch-up needs to sync. [`BlockNumber::GENESIS`] on a freshly migrated DB
    /// or before any successful catch-up has persisted a higher value.
    next_block_to_sync: BlockNumber,
    /// Account IDs that had inflight rows at startup and therefore must be reconciled against
    /// the store before normal operation: their inflight tx may have landed in a block during
    /// downtime, leaving locally-committed state stale.
    inflight_affected: Vec<NetworkAccountId>,
}

impl CatchUpInputs {
    pub(crate) fn new(
        next_block_to_sync: BlockNumber,
        inflight_affected: Vec<NetworkAccountId>,
    ) -> Self {
        Self { next_block_to_sync, inflight_affected }
    }
}

impl NetworkTransactionBuilder {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: NtxBuilderConfig,
        coordinator: Coordinator,
        store: StoreClient,
        db: Db,
        chain_state: Arc<SharedChainState>,
        actor_context: AccountActorContext,
        mempool_events: MempoolEventStream,
        actor_request_rx: mpsc::Receiver<ActorRequest>,
        catch_up: CatchUpInputs,
    ) -> Self {
        Self {
            config,
            coordinator,
            store,
            db,
            chain_state,
            actor_context,
            mempool_events,
            actor_request_rx,
            catch_up,
        }
    }

    /// Runs the network transaction builder event loop until a fatal error occurs.
    ///
    /// If a `TcpListener` is provided, a gRPC server is also spawned to expose the
    /// `GetNoteError` endpoint.
    ///
    /// This method:
    /// 1. Optionally starts a gRPC server for note error queries
    /// 2. Spawns a background task to load existing network accounts from the store
    /// 3. Runs the main event loop, processing mempool events and managing actors
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The mempool event stream ends unexpectedly
    /// - An actor encounters a fatal error
    /// - The account loader task fails
    /// - The gRPC server fails
    pub async fn run(self, listener: Option<TcpListener>) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();

        // Start the gRPC server if a listener is provided.
        if let Some(listener) = listener {
            let server = NtxBuilderRpcServer::new(self.db.clone());
            join_set.spawn(async move {
                server.serve(listener).await.context("ntx-builder gRPC server failed")
            });
        }

        join_set.spawn(self.run_event_loop());

        // Wait for either the event loop or the gRPC server to complete.
        // Any completion is treated as fatal.
        if let Some(result) = join_set.join_next().await {
            result.context("ntx-builder task panicked")??;
        }

        Ok(())
    }

    /// Runs the main event loop.
    ///
    /// Catch-up against the store runs to completion before the main `select!` opens, so the
    /// loop body only deals with steady-state events. The cost is that no network transactions
    /// are produced until catch-up finishes.
    async fn run_event_loop(mut self) -> anyhow::Result<()> {
        let inflight_set: HashSet<NetworkAccountId> =
            self.catch_up.inflight_affected.iter().copied().collect();
        self.run_store_catch_up(&inflight_set).await?;

        // Main event loop.
        loop {
            tokio::select! {
                // Handle actor result. If a timed-out actor needs respawning, do so.
                result = self.coordinator.next() => {
                    if let Some(account_id) = result? {
                        self.coordinator
                            .spawn_actor(AccountOrigin::store(account_id), &self.actor_context);
                    }
                },
                // Handle mempool events.
                event = self.mempool_events.next() => {
                    let event = event
                        .context("mempool event stream ended")?
                        .context("mempool event stream failed")?;
                    self.handle_mempool_event(event).await?;
                },
                // Handle requests from actors.
                Some(request) = self.actor_request_rx.recv() => {
                    self.handle_actor_request(request).await?;
                },
            }
        }
    }

    /// Runs startup catch-up synchronously: reconciles inflight-affected accounts, fetches state
    /// for accounts created during downtime, refreshes unconsumed notes for already-known
    /// committed accounts, and persists `next_block_to_sync` once everything succeeds.
    ///
    /// Anchored to the chain tip captured in `chain_state` at `build()` time. Events that arrive
    /// in the mempool stream during this call are buffered by the gRPC subscription and drained
    /// once the main loop opens.
    async fn run_store_catch_up(
        &mut self,
        inflight_set: &HashSet<NetworkAccountId>,
    ) -> anyhow::Result<()> {
        // 1. Reconcile inflight-affected accounts.
        for account_id in std::mem::take(&mut self.catch_up.inflight_affected) {
            self.handle_loaded_account(account_id).await.with_context(|| {
                format!("failed to reconcile inflight-affected account {account_id}")
            })?;
        }

        let catch_up_target = self.chain_state.chain_tip_block_number();
        let next_block_to_sync = self.catch_up.next_block_to_sync;
        let gap_from = (next_block_to_sync <= catch_up_target).then_some(next_block_to_sync);

        // 2. Per-account note refresh for locally-known committed accounts (excluding inflight).
        let known_accounts = self
            .db
            .list_committed_account_ids()
            .await
            .context("failed to list committed accounts")?;
        let known_to_refresh: Vec<_> =
            known_accounts.into_iter().filter(|id| !inflight_set.contains(id)).collect();

        tracing::info!(
            ?gap_from,
            catch_up_target = %catch_up_target,
            inflight_reconciled = inflight_set.len(),
            known_to_refresh = known_to_refresh.len(),
            "ntx-builder store catch-up starting"
        );

        // Refresh notes in parallel (the hydration semaphore inside `StoreClient` bounds the
        // burst). Each task returns the account ID so we can spawn its actor once done.
        let refresh_futures: Vec<_> = known_to_refresh
            .into_iter()
            .map(|account_id| {
                let store = self.store.clone();
                let db = self.db.clone();
                async move {
                    match store
                        .get_unconsumed_network_notes(account_id, catch_up_target.as_u32())
                        .await
                    {
                        Ok(notes) => {
                            if let Err(err) = db.upsert_committed_notes(notes).await {
                                tracing::error!(
                                    %account_id,
                                    error = %err,
                                    "failed to persist refreshed notes"
                                );
                            }
                        },
                        Err(err) => {
                            tracing::warn!(
                                %account_id,
                                error = %err,
                                "note refresh failed; spawning actor with possibly stale notes"
                            );
                        },
                    }
                    account_id
                }
            })
            .collect();

        // 3. Gap discovery: stream account IDs created during downtime and fully hydrate each. Done
        //    first so the per-account note refresh tasks can overlap with the streamed fetches via
        //    the shared hydration semaphore.
        if let Some(from_block) = gap_from {
            let (account_tx, mut account_rx) =
                mpsc::channel::<NetworkAccountId>(self.config.account_channel_capacity);
            let loader_store = self.store.clone();
            let loader_handle: tokio::task::JoinHandle<anyhow::Result<()>> =
                tokio::spawn(async move {
                    loader_store
                        .stream_network_account_ids(from_block, account_tx)
                        .await
                        .context("failed to load network accounts from store")
                });

            while let Some(account_id) = account_rx.recv().await {
                self.handle_loaded_account(account_id)
                    .await
                    .context("failed to hydrate streamed account during catch-up")?;
            }

            loader_handle.await.context("account loader task panicked").flatten()?;
        }

        // 4. Drain the note-refresh futures and spawn actors for each refreshed account.
        let refreshed: Vec<NetworkAccountId> = futures::future::join_all(refresh_futures).await;
        for account_id in refreshed {
            self.coordinator
                .spawn_actor(AccountOrigin::store(account_id), &self.actor_context);
        }

        // 5. Persist `next_block_to_sync`. Done last so a crash mid-catch-up leaves it pointing at
        //    the range still to sync.
        self.db
            .set_next_block_to_sync(catch_up_target.child())
            .await
            .context("failed to persist next_block_to_sync after catch-up")?;

        tracing::info!(
            catch_up_to = %catch_up_target,
            "ntx-builder catch-up complete; next_block_to_sync advanced"
        );

        Ok(())
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

        let block_num = self.chain_state.chain_tip_block_number();
        let notes = self
            .store
            .get_unconsumed_network_notes(account_id, block_num.as_u32())
            .await
            .context("failed to load notes from store")?;

        // Write account and notes to DB.
        self.db
            .sync_account_from_store(account_id, account.clone(), notes.clone())
            .await
            .context("failed to sync account to DB")?;

        self.coordinator
            .spawn_actor(AccountOrigin::store(account_id), &self.actor_context);
        Ok(())
    }

    /// Handles mempool events by writing to DB first, then notifying actors.
    #[tracing::instrument(name = "ntx.builder.handle_mempool_event", skip(self, event))]
    async fn handle_mempool_event(&mut self, event: MempoolEvent) -> Result<(), anyhow::Error> {
        match &event {
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
                            self.coordinator.spawn_actor(network_account, &self.actor_context);
                        }
                    }
                }
                let inactive_targets = self.coordinator.send_targeted(&event);
                for account_id in inactive_targets {
                    self.coordinator
                        .spawn_actor(AccountOrigin::store(account_id), &self.actor_context);
                }
                Ok(())
            },
            // Update chain state and notify affected actors.
            MempoolEvent::BlockCommitted { header, .. } => {
                // Write event effects to DB first.
                let result = self
                    .coordinator
                    .write_event(&event)
                    .await
                    .context("failed to write BlockCommitted to DB")?;

                self.chain_state
                    .update_chain_tip(header.as_ref().clone(), self.config.max_block_count);
                self.coordinator.notify_accounts(&result.accounts_to_notify);
                Ok(())
            },
            // Notify affected actors (reverted account actors will self-cancel when they
            // detect their account has been removed from the DB).
            MempoolEvent::TransactionsReverted(_) => {
                // Write event effects to DB first.
                let result = self
                    .coordinator
                    .write_event(&event)
                    .await
                    .context("failed to write TransactionsReverted to DB")?;

                self.coordinator.notify_accounts(&result.accounts_to_notify);
                Ok(())
            },
        }
    }

    /// Processes a request from an account actor.
    async fn handle_actor_request(&mut self, request: ActorRequest) -> Result<(), anyhow::Error> {
        match request {
            ActorRequest::NotesFailed { failed_notes, block_num, ack_tx } => {
                self.db
                    .notes_failed(failed_notes, block_num)
                    .await
                    .context("failed to mark notes as failed")?;
                let _ = ack_tx.send(());
            },
            ActorRequest::CacheNoteScript { script_root, script } => {
                self.db
                    .insert_note_script(script_root, &script)
                    .await
                    .context("failed to cache note script")?;
            },
        }
        Ok(())
    }
}
