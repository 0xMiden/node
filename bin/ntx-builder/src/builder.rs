use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use futures::Stream;
use miden_protocol::block::{BlockNumber, SignedBlock};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::StreamExt;

use crate::NtxBuilderConfig;
use crate::actor::{AccountActorContext, ActorRequest};
use crate::chain_state::SharedChainState;
use crate::clients::store::StoreError;
use crate::committed_block::CommittedBlockEffects;
use crate::coordinator::Coordinator;
use crate::db::Db;
use crate::server::NtxBuilderRpcServer;

// NETWORK TRANSACTION BUILDER
// ================================================================================================

/// A boxed, pinned stream of committed blocks coming from the store.
///
/// Boxing gives the stream a `'static` lifetime by ensuring it owns all its data, avoiding
/// complex lifetime annotations that would otherwise be required when storing `impl Stream`.
pub(crate) type BlockStream = Pin<Box<dyn Stream<Item = Result<SignedBlock, StoreError>> + Send>>;

/// Network transaction builder component.
///
/// The network transaction builder is in charge of building transactions that consume notes
/// against network accounts. These notes are identified by the store's committed block stream.
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
    /// Database for persistent state.
    db: Db,
    /// Shared chain state updated by the event loop and read by actors.
    chain_state: Arc<SharedChainState>,
    /// Context shared with all account actors.
    actor_context: AccountActorContext,
    /// Stream of committed blocks from the store.
    block_stream: BlockStream,
    /// Highest block number applied to the DB so far.
    last_applied_block: BlockNumber,
    /// Database update requests from account actors.
    ///
    /// We keep database writes centralized so this is how actors communicate
    /// items to write.
    actor_request_rx: mpsc::Receiver<ActorRequest>,
}

impl NetworkTransactionBuilder {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: NtxBuilderConfig,
        coordinator: Coordinator,
        db: Db,
        chain_state: Arc<SharedChainState>,
        actor_context: AccountActorContext,
        block_stream: BlockStream,
        last_applied_block: BlockNumber,
        actor_request_rx: mpsc::Receiver<ActorRequest>,
    ) -> Self {
        Self {
            config,
            coordinator,
            db,
            chain_state,
            actor_context,
            block_stream,
            last_applied_block,
            actor_request_rx,
        }
    }

    /// Runs the network transaction builder event loop until a fatal error occurs.
    ///
    /// If a `TcpListener` is provided, a gRPC server is also spawned to expose the
    /// `GetNetworkNoteStatus` endpoint.
    ///
    /// This method:
    /// 1. Starts a gRPC server for note error queries.
    /// 2. Catches up to the chain tip by draining the block stream. No actors run during this
    ///    phase.
    /// 3. Spawns a background task to load existing network accounts from the store.
    /// 4. Runs the main event loop, processing committed blocks and managing actors.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The block stream ends unexpectedly
    /// - An actor encounters a fatal error
    /// - The account loader task fails
    /// - The gRPC server fails
    pub async fn run(mut self, listener: TcpListener) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();

        // Start the gRPC server.
        let server = NtxBuilderRpcServer::new(self.db.clone(), self.config.max_note_attempts);
        join_set.spawn(async move {
            server.serve(listener).await.context("ntx-builder gRPC server failed")
        });

        // Spawn actors for accounts that have unconsumed notes inherited from a previous run.
        // Accounts touched by the live stream are spawned reactively via send_targeted.
        let pending = self
            .db
            .accounts_with_pending_notes()
            .await
            .context("failed to query accounts with pending notes")?;
        if !pending.is_empty() {
            tracing::info!(count = pending.len(), "spawning actors for inherited pending notes");
            for account_id in pending {
                self.coordinator.spawn_actor(account_id, &self.actor_context);
            }
        }

        join_set.spawn(self.run_event_loop());

        // Wait for either the event loop or the gRPC server to complete. Any completion is treated
        // as fatal.
        if let Some(result) = join_set.join_next().await {
            result.context("ntx-builder task panicked")??;
        }

        Ok(())
    }

    /// Runs the main event loop.
    async fn run_event_loop(mut self) -> anyhow::Result<()> {
        // Main event loop.
        loop {
            tokio::select! {
                // Handle actor result. If a timed-out actor needs respawning, do so.
                result = self.coordinator.next() => {
                    if let Some(account_id) = result? {
                        self.coordinator
                            .spawn_actor(account_id, &self.actor_context);
                    }
                },
                // Handle committed blocks.
                block = self.block_stream.next() => {
                    let block = block
                        .context("block stream ended")?
                        .context("block stream failed")?;

                    self.handle_committed_block(block).await?;
                },
                // Handle requests from actors.
                Some(request) = self.actor_request_rx.recv() => {
                    self.handle_actor_request(request).await?;
                },
            }
        }
    }

    /// Handles a committed block from the stream: persists effects together with the new chain
    /// MMR, advances in-memory chain state, and notifies (or spawns) affected actors.
    #[tracing::instrument(
        name = "ntx.builder.handle_committed_block",
        skip(self, block),
        fields(block.num = %block.header().block_num()),
    )]
    async fn handle_committed_block(&mut self, block: SignedBlock) -> Result<(), anyhow::Error> {
        let header = block.header().clone();
        let block_num = header.block_num();
        let effects = CommittedBlockEffects::from_signed_block(&block);

        // Compute the chain MMR that will result from advancing to this block, then persist it
        // atomically with the block effects so the DB stays consistent across restarts.
        let next_mmr = self.chain_state.next_chain_mmr(&header, self.config.max_block_count);

        let result = self
            .coordinator
            .apply_block(&effects, next_mmr)
            .await
            .context("failed to apply committed block to DB")?;

        self.chain_state.update_chain_tip(header, self.config.max_block_count);
        self.last_applied_block = block_num;

        // Respawn inactive actors targeted by new notes and notify any active actor whose state
        // changed.
        let inactive_targets = self.coordinator.send_targeted(&effects);
        for account_id in inactive_targets {
            self.coordinator.spawn_actor(account_id, &self.actor_context);
        }
        // Spawn actors for newly-observed network accounts whose state changed but didn't receive
        // a new note (e.g. a delta-only update).
        for (account_id, _details) in &effects.network_account_updates {
            if !self.coordinator.has_actor(*account_id) {
                self.coordinator.spawn_actor(*account_id, &self.actor_context);
            }
        }
        self.coordinator.notify_accounts(&result.accounts_to_notify);

        // Also notify every active actor so any actor currently waiting on its own submitted
        // transaction wakes up, even if its account wasn't touched by this block (e.g. tx was
        // dropped or expired without inclusion).
        self.coordinator.notify_all();

        Ok(())
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
