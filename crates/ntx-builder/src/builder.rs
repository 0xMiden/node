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
    /// Bookkeeping for the startup catch-up phase. Owned by the run loop and consulted on every
    /// `BlockCommitted` event to decide whether to advance the store-sync watermark.
    catch_up: CatchUpState,
}

/// State that drives the ntx-builder's startup catch-up.
pub(crate) struct CatchUpState {
    /// Persisted store-sync checkpoint from the previous run, or `None` on first-ever startup
    /// (or before any successful catch-up). Scopes the gap that startup catch-up needs to
    /// bridge.
    prev_local_block: Option<BlockNumber>,
    /// Account IDs that had inflight rows at startup and therefore must be reconciled against
    /// the store before normal operation: their inflight tx may have landed in a block during
    /// downtime, leaving locally-committed state stale.
    inflight_affected: Vec<NetworkAccountId>,
    /// Keeps the state of the catch up process.
    complete: bool,
}

impl CatchUpState {
    pub(crate) fn new(
        prev_local_block: Option<BlockNumber>,
        inflight_affected: Vec<NetworkAccountId>,
    ) -> Self {
        Self {
            prev_local_block,
            inflight_affected,
            complete: false,
        }
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
        catch_up: CatchUpState,
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
    async fn run_event_loop(mut self) -> anyhow::Result<()> {
        // Reconcile inflight-affected accounts.
        //
        // For each account that had an inflight row at startup, do a full hydration
        // (account-details + unconsumed-notes) from the store. The inflight tx may have
        // landed in a block we didn't witnessed, so locally-committed state cannot be
        // trusted for these specific accounts. The set is bounded by `max_concurrent_txs`
        // so this is small and we run it sequentially before opening the main loop.
        let inflight_set: HashSet<NetworkAccountId> =
            self.catch_up.inflight_affected.iter().copied().collect();
        for account_id in std::mem::take(&mut self.catch_up.inflight_affected) {
            if let Err(err) = self.handle_loaded_account(account_id).await {
                tracing::error!(
                    %account_id,
                    error = %err,
                    "failed to reconcile inflight-affected account; will retry on next event"
                );
            }
        }

        // Setup hydration channels.
        let (account_tx, mut account_rx) =
            mpsc::channel::<NetworkAccountId>(self.config.account_channel_capacity);
        let (note_refresh_done_tx, mut note_refresh_done_rx) =
            mpsc::channel::<NetworkAccountId>(self.config.account_channel_capacity);
        let (catch_up_done_tx, mut catch_up_done_rx) = mpsc::channel::<BlockNumber>(1);

        let prev_local_block = self.catch_up.prev_local_block;
        let mut catch_up_started = false;
        let mut account_loader_handle: tokio::task::JoinHandle<anyhow::Result<()>> =
            tokio::spawn(async move { Ok(()) });
        // Take the senders out of `self` so we can move them into the kickoff closure.
        let mut account_tx_holder = Some(account_tx);
        let mut note_refresh_done_tx_holder = Some(note_refresh_done_tx);
        let mut catch_up_done_tx_holder = Some(catch_up_done_tx);

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

                    let kickoff_block = if catch_up_started {
                        None
                    } else {
                        match &event {
                            MempoolEvent::BlockCommitted { header, .. } => {
                                Some(header.block_num())
                            },
                            _ => None,
                        }
                    };

                    self.handle_mempool_event(event).await?;

                    if let Some(m) = kickoff_block {
                        catch_up_started = true;
                        let account_tx = account_tx_holder.take().expect("kickoff runs once");
                        let note_refresh_done_tx =
                            note_refresh_done_tx_holder.take().expect("kickoff runs once");
                        let catch_up_done_tx =
                            catch_up_done_tx_holder.take().expect("kickoff runs once");
                        account_loader_handle = Self::kickoff_catch_up(
                            self.store.clone(),
                            self.db.clone(),
                            prev_local_block,
                            m,
                            &inflight_set,
                            account_tx,
                            note_refresh_done_tx,
                            catch_up_done_tx,
                        )
                        .await?;
                    }
                },
                // Gap discovery: a new account ID created during downtime. Full 2-call hydration.
                Some(account_id) = account_rx.recv() => {
                    self.handle_loaded_account(account_id).await?;
                },
                // Per-known-account note refresh complete: spawn its actor.
                Some(account_id) = note_refresh_done_rx.recv() => {
                    self.coordinator
                        .spawn_actor(AccountOrigin::store(account_id), &self.actor_context);
                },
                // Store catch-up finished: flip the flag and bump store_sync_checkpoint to
                // `block_number`.
                Some(block_number) = catch_up_done_rx.recv() => {
                    self.catch_up.complete = true;
                    if let Err(err) = self.db.set_store_sync_checkpoint(block_number).await {
                        tracing::error!(
                            error = %err,
                            "failed to persist store_sync_checkpoint after catch-up"
                        );
                    }
                    tracing::info!(
                        catch_up_to = %block_number,
                        "ntx-builder catch-up complete; sync watermark set"
                    );
                },
                // Handle requests from actors.
                Some(request) = self.actor_request_rx.recv() => {
                    self.handle_actor_request(request).await?;
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

    /// Spawns the store catch-up tasks (gap discovery + per-account note refresh) and
    /// returns the join handle for the gap-discovery task.
    ///
    /// For each locally-known committed account that is NOT in `inflight_set` (those have
    /// already been reconciled by the inflight-reconcile pass), spawns a task that fetches
    /// the unconsumed-notes delta as of block `M` and writes it. On task completion, the account
    /// ID flows through `note_refresh_done_tx` so the main loop can spawn the actor.
    ///
    /// A coordinator task waits for both gap discovery and all note-refresh tasks to
    /// finish, then signals via `catch_up_done_tx` so the main loop can flip the
    /// catch-up flag and persist the watermark.
    #[expect(clippy::too_many_arguments)]
    async fn kickoff_catch_up(
        store: StoreClient,
        db: Db,
        prev_local_block: Option<BlockNumber>,
        catch_up_target: BlockNumber,
        inflight_set: &HashSet<NetworkAccountId>,
        account_tx: mpsc::Sender<NetworkAccountId>,
        note_refresh_done_tx: mpsc::Sender<NetworkAccountId>,
        catch_up_done_tx: mpsc::Sender<BlockNumber>,
    ) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
        let gap_from = match prev_local_block {
            Some(prev) if prev < catch_up_target => {
                Some(BlockNumber::from(prev.as_u32().saturating_add(1)))
            },
            Some(_) => None,
            None => Some(BlockNumber::GENESIS),
        };

        // Spawn the gap-discovery loader (or a no-op task if there's nothing to bridge).
        let account_loader_handle: tokio::task::JoinHandle<anyhow::Result<()>> =
            if let Some(from_block) = gap_from {
                let loader_store = store.clone();
                tokio::spawn(async move {
                    loader_store
                        .stream_network_account_ids(from_block, account_tx)
                        .await
                        .context("failed to load network accounts from store")
                })
            } else {
                drop(account_tx);
                tokio::spawn(async move { Ok::<(), anyhow::Error>(()) })
            };

        // Per-account note refresh for locally-known committed accounts (excluding inflight).
        let known_accounts = db
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
            "ntx-builder store catch-up kicked off"
        );

        let mut refresh_handles: Vec<tokio::task::JoinHandle<()>> =
            Vec::with_capacity(known_to_refresh.len());
        for account_id in known_to_refresh {
            let task_store = store.clone();
            let task_db = db.clone();
            let done_tx = note_refresh_done_tx.clone();
            refresh_handles.push(tokio::spawn(async move {
                // The hydration semaphore is acquired inside `get_unconsumed_network_notes`.
                match task_store
                    .get_unconsumed_network_notes(account_id, catch_up_target.as_u32())
                    .await
                {
                    Ok(notes) => {
                        if let Err(err) = task_db.upsert_committed_notes(notes).await {
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
                // Always signal completion so the actor still spawns even if refresh failed.
                let _ = done_tx.send(account_id).await;
            }));
        }
        // Drop the local sender so the channel closes once all spawned refresh tasks finish.
        drop(note_refresh_done_tx);

        tokio::spawn(async move {
            for handle in refresh_handles {
                let _ = handle.await;
            }
            let _ = catch_up_done_tx.send(catch_up_target).await;
        });

        Ok(account_loader_handle)
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
                    .write_event(&event, self.catch_up.complete)
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
                    .write_event(&event, self.catch_up.complete)
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
                    .write_event(&event, self.catch_up.complete)
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
