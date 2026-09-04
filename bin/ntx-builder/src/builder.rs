use std::pin::Pin;

use anyhow::Context;
use futures::Stream;
use miden_node_tracing::{info, miden_instrument};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_protocol::block::{BlockNumber, SignedBlock};
use tokio::net::TcpListener;
use tokio_stream::StreamExt;

use crate::attempt::AttemptOutcome;
use crate::chain_state::ChainState;
use crate::clients::RpcError;
use crate::committed_block::CommittedBlockEffects;
use crate::db::NtxDbWriter;
use crate::scheduler::Scheduler;
use crate::server::NtxBuilderRpcServer;
use crate::{LOG_TARGET, NtxBuilderConfig};

/// Discriminator returned by the steady-state `select!` so the dispatch can run on a fully-owned
/// `&mut self` instead of two concurrent borrows. The `Block` variant is boxed since a
/// `SignedBlock` dwarfs the other payloads.
enum SteadyStateAction {
    Block(Box<Option<Result<(SignedBlock, BlockNumber), RpcError>>>),
    Completion(anyhow::Result<AttemptOutcome>),
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
/// Runs in two phases:
/// 1. **Catch-up**: drain the committed-block subscription, applying each block to the local DB and
///    in-memory chain, until the local tip matches the node-reported `committed_chain_tip`
///    (signaled by `is_synced` flipping to `true`). No transaction attempts run.
/// 2. **Steady-state**: on every committed block, apply the effects, advance the chain, resolve the
///    scheduler's in-flight transactions against the block, and fill the free attempt slots.
///    Concurrently reap finished attempts, persisting the note bookkeeping each one reports.
pub struct NetworkTransactionBuilder {
    /// Configuration for the builder.
    config: NtxBuilderConfig,
    /// Database for persistent state.
    db: NtxDbWriter,
    /// Stream of committed blocks from the node RPC service.
    block_stream: BlockStream,
    /// Highest block number applied to the DB so far.
    last_applied_block: BlockNumber,
    /// In-memory partial chain.
    chain: ChainState,
    /// Owner of the transaction attempts and of the in-flight transaction set.
    scheduler: Scheduler,
    /// `false` until the first applied block whose `committed_chain_tip` matches the just-applied
    /// block number. Stays `true` afterwards.
    is_synced: bool,
}

impl NetworkTransactionBuilder {
    pub(crate) fn new(
        config: NtxBuilderConfig,
        db: NtxDbWriter,
        block_stream: BlockStream,
        last_applied_block: BlockNumber,
        chain: ChainState,
        scheduler: Scheduler,
    ) -> Self {
        Self {
            config,
            db,
            block_stream,
            last_applied_block,
            chain,
            scheduler,
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
        let server = NtxBuilderRpcServer::new(
            self.db.reader(),
            self.config.max_note_attempts,
            self.config.grpc_timeout,
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
            let (block, committed_tip) = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.next_block() => result?,
            };
            let local_tip = block.header().block_num();
            self.apply_committed_block(block, committed_tip).await?;

            if local_tip == committed_tip {
                self.is_synced = true;
                info!(
                    target: LOG_TARGET,
                    "ntx-builder is now in sync",
                    block.number = committed_tip
                );
                break;
            }
        }

        // Phase 2: work the accounts that have pending notes, one attempt per free slot, driven by
        // committed blocks and by the completion of earlier attempts.
        self.scheduler.dispatch(&self.chain).await?;

        loop {
            // Split `&mut self` into disjoint borrows so each `select!` arm holds only the one
            // field it polls. The action is materialised and self is released before the body
            // dispatches the work via the regular `&mut self` methods.
            let action = {
                let block_stream = &mut self.block_stream;
                let scheduler = &mut self.scheduler;

                tokio::select! {
                    () = shutdown.cancelled() => SteadyStateAction::Shutdown,
                    block = block_stream.next() => SteadyStateAction::Block(Box::new(block)),
                    completion = scheduler.next_completion() => {
                        SteadyStateAction::Completion(completion)
                    },
                }
            };

            match action {
                SteadyStateAction::Block(block) => {
                    let (block, committed_tip) =
                        (*block).context("block stream ended")?.context("block stream failed")?;
                    let effects =
                        self.apply_committed_block_with_effects(block, committed_tip).await?;
                    self.scheduler.handle_committed_block(&effects);
                    self.scheduler.dispatch(&self.chain).await?;
                },
                SteadyStateAction::Completion(outcome) => {
                    if self.scheduler.handle_completion(&self.db, outcome?).await? {
                        self.scheduler.dispatch(&self.chain).await?;
                    }
                },
                SteadyStateAction::Shutdown => {
                    self.scheduler.shutdown().await;
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
        block: SignedBlock,
        committed_tip: BlockNumber,
    ) -> anyhow::Result<()> {
        self.apply_committed_block_with_effects(block, committed_tip).await.map(drop)
    }

    /// Applies a committed block and returns the computed [`CommittedBlockEffects`], so the caller
    /// can resolve the scheduler's in-flight transactions against the same effects without
    /// re-deriving them from the signed block.
    #[miden_instrument(
        name = "ntx.builder.apply_committed_block",
        fields(
            block.number = block.header().block_num(),
            tip.number = committed_tip,
        ),
    )]
    async fn apply_committed_block_with_effects(
        &mut self,
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

        let effects_for_db = effects.clone();
        self.db
            .apply_committed_block(effects_for_db, next_mmr)
            .await
            .context("failed to apply committed block to DB")?;

        self.last_applied_block = block_num;

        Ok(effects)
    }
}
