use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use futures::Stream;
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::block::{BlockNumber, SignedBlock};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use crate::actor::ActorRequest;
use crate::chain_state::SharedChainState;
use crate::clients::RpcError;
use crate::committed_block::CommittedBlockEffects;
use crate::coordinator::Coordinator;
use crate::db::{Db, LoopDb};
use crate::server::NtxBuilderRpcServer;
use crate::{LOG_TARGET, NtxBuilderConfig};

/// Discriminator returned by the steady-state `select!` so the dispatch can run on a fully-owned
/// `&mut self` instead of three concurrent borrows. The `Block` variant is boxed since a
/// `SignedBlock` dwarfs the other two payloads.
enum SteadyStateAction {
    Block(Box<Option<Result<(SignedBlock, BlockNumber), RpcError>>>),
    Request(Option<ActorRequest>),
    Respawn(Option<miden_protocol::account::AccountId>),
    Shutdown,
}

// NETWORK TRANSACTION BUILDER
// ================================================================================================

/// Boxed, pinned stream of committed blocks paired with the node-reported committed chain tip at
/// the time each block was emitted.
///
/// Boxing gives the stream a `'static` lifetime by ensuring it owns all its data, avoiding the
/// complex lifetime annotations otherwise required to store `impl Stream`.
pub(crate) type BlockStream =
    Pin<Box<dyn Stream<Item = Result<(SignedBlock, BlockNumber), RpcError>> + Send>>;

/// Network transaction builder component.
///
/// Runs in three phases:
/// 1. **Catch-up**: drain the committed-block subscription, applying each block to the local DB
///    and in-memory chain, until the local tip matches the node-reported `committed_chain_tip`
///    (signaled by `is_synced` flipping to `true`). No actors run.
/// 2. **Boundary**: query the DB for accounts with carry-over pending notes (e.g. from a previous
///    process) and spawn an actor for each.
/// 3. **Steady-state**: on every subsequent committed block, apply the effects, advance the chain,
///    and have the coordinator spawn-if-missing for newly-targeted accounts then wake every active
///    actor. Concurrently drain actor requests (`NotesFailed`, `CacheNoteScript`) so the actors'
///    DB writes happen serialized through the builder.
pub struct NetworkTransactionBuilder {
    /// Configuration for the builder.
    config: NtxBuilderConfig,
    /// Database for persistent state.
    db: Db,
    /// Stream of committed blocks from the node RPC service.
    block_stream: BlockStream,
    /// Highest block number applied to the DB so far.
    last_applied_block: BlockNumber,
    /// In-memory partial chain shared with every spawned actor through the coordinator.
    chain: Arc<SharedChainState>,
    /// Lifecycle owner for `AccountActor` instances.
    coordinator: Coordinator,
    /// Channel receiving DB-side requests (note-failed bookkeeping, script-cache persistence) from
    /// spawned actors. Drained in the steady-state loop so writes happen through the builder.
    actor_request_rx: mpsc::Receiver<ActorRequest>,
    /// `false` until the first applied block whose `committed_chain_tip` matches the just-applied
    /// block number. Stays `true` afterwards.
    is_synced: bool,
}

impl NetworkTransactionBuilder {
    pub(crate) fn new(
        config: NtxBuilderConfig,
        db: Db,
        block_stream: BlockStream,
        last_applied_block: BlockNumber,
        chain: Arc<SharedChainState>,
        coordinator: Coordinator,
        actor_request_rx: mpsc::Receiver<ActorRequest>,
    ) -> Self {
        Self {
            config,
            db,
            block_stream,
            last_applied_block,
            chain,
            coordinator,
            actor_request_rx,
            is_synced: false,
        }
    }

    /// Returns `true` once the builder has caught up to the node's committed chain tip at least
    /// once. Stays `true` for the lifetime of the process.
    pub fn is_synced(&self) -> bool {
        self.is_synced
    }

    /// Runs the network transaction builder event loop until a fatal error occurs.
    pub async fn run(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut tasks = Tasks::new();

        // Start the gRPC server.
        let server = NtxBuilderRpcServer::new(self.db.clone(), self.config.max_note_attempts);
        let server_shutdown = shutdown.clone();
        tasks.spawn("grpc-server", async move {
            server
                .serve(listener, server_shutdown)
                .await
                .context("ntx-builder gRPC server failed")
        });

        tasks.spawn("event-loop", self.run_event_loop(shutdown.clone()));

        // Wait for either the event loop or the gRPC server to complete. Any completion is treated
        // as fatal.
        tasks.join_next_or_cancelled(shutdown).await.context("ntx-builder task failed")
    }

    async fn run_event_loop(mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // Pin a dedicated connection for the loop's DB writes so block application is never starved
        // by the account actors competing for the shared pool.
        let loop_db = self
            .db
            .pin_loop_connection()
            .await
            .context("failed to pin a database connection for the ntx-builder event loop")?;

        // Phase 1: catch-up.
        loop {
            let (block, committed_tip) = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.next_block() => result?,
            };
            let local_tip = block.header().block_num();
            self.apply_committed_block(&loop_db, block, committed_tip).await?;

            if local_tip == committed_tip {
                self.is_synced = true;
                tracing::info!(
                    target: LOG_TARGET,
                    { block.number = %committed_tip },
                    "ntx-builder is now in sync"
                );
                break;
            }
        }

        // Phase 2: spawn an actor for every account with carry-over pending notes. Accounts whose
        // creation has not been committed yet have their spawn deferred by the coordinator.
        let pending_accounts = loop_db
            .accounts_with_pending_notes(self.config.max_note_attempts)
            .await
            .context("failed to load accounts with pending notes at catch-up")?;
        tracing::info!(
            target: LOG_TARGET,
            num_accounts = pending_accounts.len(),
            "spawning actors for accounts with carry-over pending notes",
        );
        for account_id in pending_accounts {
            self.coordinator.spawn_actor_when_committed(account_id).await?;
        }

        // Phase 3: drive actors per committed block, plus serialize their DB writes.
        loop {
            // Split `&mut self` into disjoint borrows so each `select!` arm holds only the one
            // field it polls. The action is materialised and self is released before the body
            // dispatches the work via the regular `&mut self` methods.
            let action = {
                let block_stream = &mut self.block_stream;
                let actor_request_rx = &mut self.actor_request_rx;
                let coordinator = &mut self.coordinator;

                tokio::select! {
                    () = shutdown.cancelled() => SteadyStateAction::Shutdown,
                    block = block_stream.next() => SteadyStateAction::Block(Box::new(block)),
                    request = actor_request_rx.recv() => SteadyStateAction::Request(request),
                    respawn = coordinator.next() => SteadyStateAction::Respawn(respawn?),
                }
            };

            match action {
                SteadyStateAction::Block(block) => {
                    let (block, committed_tip) =
                        (*block).context("block stream ended")?.context("block stream failed")?;
                    let effects = self
                        .apply_committed_block_with_effects(&loop_db, block, committed_tip)
                        .await?;
                    self.coordinator.handle_committed_block(&effects).await?;
                },
                SteadyStateAction::Request(request) => {
                    let Some(request) = request else {
                        anyhow::bail!("actor request channel closed unexpectedly");
                    };
                    handle_actor_request(&loop_db, request).await?;
                },
                SteadyStateAction::Respawn(respawn) => {
                    if let Some(account_id) = respawn {
                        tracing::info!(
                            target: LOG_TARGET,
                            { account.id = %account_id },
                            "respawning actor that shut down with a pending notification",
                        );
                        self.coordinator.spawn_actor(account_id);
                    }
                },
                SteadyStateAction::Shutdown => {
                    self.coordinator.shutdown().await?;
                    return Ok(());
                },
            }
        }
    }

    /// Pulls the next `(block, committed_tip)` pair from the subscription, surfacing both the
    /// "stream ended" and per-item RPC errors as `anyhow::Error`.
    async fn next_block(&mut self) -> anyhow::Result<(SignedBlock, BlockNumber)> {
        self.block_stream
            .next()
            .await
            .context("block stream ended")?
            .context("block stream failed")
    }

    /// Applies a committed block without surfacing the computed effects.
    async fn apply_committed_block(
        &mut self,
        loop_db: &LoopDb,
        block: SignedBlock,
        committed_tip: BlockNumber,
    ) -> anyhow::Result<()> {
        self.apply_committed_block_with_effects(loop_db, block, committed_tip)
            .await
            .map(drop)
    }

    /// Applies a committed block and returns the computed `CommittedBlockEffects` so the
    /// steady-state loop can hand them to the coordinator without re-deriving from the signed
    /// block.
    #[miden_instrument(
        name = "ntx.builder.apply_committed_block",
        skip(self, loop_db, block),
        fields(
            block_num = %block.header().block_num(),
            %committed_tip,
        ),
    )]
    async fn apply_committed_block_with_effects(
        &mut self,
        loop_db: &LoopDb,
        block: SignedBlock,
        committed_tip: BlockNumber,
    ) -> anyhow::Result<CommittedBlockEffects> {
        let header = block.header().clone();
        let block_num = header.block_num();

        let effects = CommittedBlockEffects::from_signed_block(&block);

        // Advance the in-memory chain (adds the previous tip header as an MMR leaf and prunes older
        // tracked headers) before snapshotting the MMR for persistence.
        self.chain.update_chain_tip(header, self.config.max_block_count);
        let next_mmr = self.chain.current_mmr();

        loop_db
            .apply_committed_block(effects.clone(), next_mmr)
            .await
            .context("failed to apply committed block to DB")?;

        self.last_applied_block = block_num;

        Ok(effects)
    }
}

/// Handles a single actor request then acknowledges the actor. Runs on the pinned loop connection
/// so the actors' shared pool cannot starve these writes.
async fn handle_actor_request(loop_db: &LoopDb, request: ActorRequest) -> anyhow::Result<()> {
    match request {
        ActorRequest::NotesFailed { failed_notes, block_num, ack_tx } => {
            loop_db
                .notes_failed(failed_notes, block_num)
                .await
                .context("failed to persist note failure")?;
            let _ = ack_tx.send(());
        },
        ActorRequest::CacheNoteScript { script_root, script } => {
            loop_db
                .insert_note_script(script_root, &script)
                .await
                .context("failed to cache note script")?;
        },
    }
    Ok(())
}
