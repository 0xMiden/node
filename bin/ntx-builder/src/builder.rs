use anyhow::Context;
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use tokio::net::TcpListener;

use crate::NtxBuilderConfig;
use crate::chain_state::ChainState;
use crate::clients::BlockSubscriptionEvent;
use crate::db::NtxDbWriter;
use crate::network_transaction::NetworkTransactionOutcome;
use crate::scheduler::Scheduler;
use crate::server::NtxBuilderRpcServer;
use crate::sync::{BlockFollower, BlockStream};

/// Discriminator returned by the steady-state `select!` so the dispatch can run on a fully-owned
/// `&mut self` instead of two concurrent borrows. The `Block` variant is boxed since a
/// `SignedBlock` dwarfs the other payloads.
enum SteadyStateAction {
    Block(Box<anyhow::Result<BlockSubscriptionEvent>>),
    Completion(anyhow::Result<NetworkTransactionOutcome>),
    Shutdown,
}

// NETWORK TRANSACTION BUILDER
// ================================================================================================

/// Network transaction builder component.
///
/// Runs in two phases:
/// 1. **Catch-up**: drain the committed-block subscription, applying each block to the local DB and
///    in-memory chain, until the local tip matches the node-reported `committed_chain_tip`
///    (signaled by `is_synced` flipping to `true`). No network transaction is built.
/// 2. **Steady-state**: on every committed block, apply the effects, advance the chain, resolve the
///    scheduler's in-flight transactions against the block, and fill the free build slots.
///    Concurrently reap finished builds, persisting the note bookkeeping each one reports.
pub struct NetworkTransactionBuilder {
    /// Configuration for the builder.
    config: NtxBuilderConfig,
    /// Database for persistent state.
    db: NtxDbWriter,
    /// Follows committed blocks and maintains the published chain snapshot.
    follower: BlockFollower,
    /// Owner of the network transaction builds and of the in-flight transaction set.
    scheduler: Scheduler,
}

impl NetworkTransactionBuilder {
    pub(crate) fn new(
        config: NtxBuilderConfig,
        db: NtxDbWriter,
        block_stream: BlockStream,
        chain: ChainState,
        scheduler: Scheduler,
    ) -> Self {
        let follower =
            BlockFollower::new(block_stream, chain, config.max_block_count, config.note_retention);
        Self { config, db, follower, scheduler }
    }

    /// Returns `true` once the builder has caught up to the node's committed chain tip at least
    /// once. Stays `true` for the lifetime of the process.
    pub fn is_synced(&self) -> bool {
        self.follower.is_synced()
    }

    /// Runs the network transaction builder event loop until a fatal error occurs.
    pub async fn run(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut tasks = Tasks::new();

        // Start the gRPC server.
        let server = NtxBuilderRpcServer::new(
            self.db.reader(),
            self.config.max_note_attempts,
            self.config.grpc_timeout,
            self.config.max_decoding_message_size,
        );
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
        // Phase 1: catch-up.
        loop {
            let (block, committed_tip, protocol_config) = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.follower.next_block() => result?,
            };
            self.follower.apply(&self.db, block, committed_tip, protocol_config).await?;
            if self.follower.is_synced() {
                break;
            }
        }

        // Phase 2: work the accounts that have pending notes, one build per free slot, driven by
        // committed blocks and by the completion of earlier builds.
        self.scheduler.dispatch(self.follower.chain()).await?;

        loop {
            // Split `&mut self` into disjoint borrows so each `select!` arm holds only the one
            // field it polls. The action is materialised and self is released before the body
            // dispatches the work via the regular `&mut self` methods.
            let action = {
                let follower = &mut self.follower;
                let scheduler = &mut self.scheduler;

                tokio::select! {
                    () = shutdown.cancelled() => SteadyStateAction::Shutdown,
                    block = follower.next_block() => SteadyStateAction::Block(Box::new(block)),
                    completion = scheduler.next_completion() => {
                        SteadyStateAction::Completion(completion)
                    },
                }
            };

            match action {
                SteadyStateAction::Block(block) => {
                    let (block, committed_tip, protocol_config) = (*block)?;
                    let effects = self
                        .follower
                        .apply(&self.db, block, committed_tip, protocol_config)
                        .await?;
                    self.scheduler.handle_committed_block(&effects);
                    self.scheduler.dispatch(self.follower.chain()).await?;
                },
                SteadyStateAction::Completion(outcome) => {
                    if self.scheduler.handle_completion(&self.db, outcome?).await? {
                        self.scheduler.dispatch(self.follower.chain()).await?;
                    }
                },
                SteadyStateAction::Shutdown => {
                    self.scheduler.shutdown().await;
                    return Ok(());
                },
            }
        }
    }
}
