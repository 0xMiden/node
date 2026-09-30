use std::pin::Pin;

use anyhow::Context;
use futures::Stream;
use miden_node_tracing::{info, miden_instrument};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::protocol_config::ProtocolConfig;
use tokio::net::TcpListener;
use tokio_stream::StreamExt;

use crate::chain_state::ChainState;
use crate::clients::{BlockSubscriptionEvent, RpcError};
use crate::committed_block::CommittedBlockEffects;
use crate::db::NtxDbWriter;
use crate::network_transaction::NetworkTransactionOutcome;
use crate::scheduler::Scheduler;
use crate::server::NtxBuilderRpcServer;
use crate::{LOG_TARGET, NtxBuilderConfig};

/// Discriminator returned by the steady-state `select!` so the dispatch can run on a fully-owned
/// `&mut self` instead of two concurrent borrows. The `Block` variant is boxed since a
/// `SignedBlock` dwarfs the other payloads.
enum SteadyStateAction {
    Block(Box<Option<Result<BlockSubscriptionEvent, RpcError>>>),
    Completion(anyhow::Result<NetworkTransactionOutcome>),
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
    Pin<Box<dyn Stream<Item = Result<BlockSubscriptionEvent, RpcError>> + Send>>;

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
    /// Stream of committed blocks from the node RPC service.
    block_stream: BlockStream,
    /// Highest block number applied to the DB so far.
    last_applied_block: BlockNumber,
    /// In-memory partial chain.
    chain: ChainState,
    /// Owner of the network transaction builds and of the in-flight transaction set.
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
            let (block, committed_tip, protocol_config) = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.next_block() => result?,
            };
            let local_tip = block.header().block_num();
            self.apply_committed_block(block, committed_tip, protocol_config).await?;

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

        // Phase 2: work the accounts that have pending notes, one build per free slot, driven by
        // committed blocks and by the completion of earlier builds.
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
                    let (block, committed_tip, protocol_config) =
                        (*block).context("block stream ended")?.context("block stream failed")?;
                    let effects = self
                        .apply_committed_block_with_effects(block, committed_tip, protocol_config)
                        .await?;
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

    /// Pulls the next block event from the subscription. This method returns stream and item
    /// errors.
    async fn next_block(&mut self) -> anyhow::Result<BlockSubscriptionEvent> {
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
        protocol_config: Option<ProtocolConfig>,
    ) -> anyhow::Result<()> {
        self.apply_committed_block_with_effects(block, committed_tip, protocol_config)
            .await
            .map(drop)
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
        protocol_config: Option<ProtocolConfig>,
    ) -> anyhow::Result<CommittedBlockEffects> {
        let block_num = block.header().block_num();

        // Build the next immutable snapshot before persistence. Do not publish it until the
        // database transaction commits.
        let next_chain =
            self.chain
                .next_chain_tip(&block, protocol_config, self.config.max_block_count)?;

        let effects = CommittedBlockEffects::from_signed_block(&block);
        let effects_for_db = effects.clone();
        persist_and_publish_chain_state(&self.db, &mut self.chain, effects_for_db, next_chain)
            .await?;

        self.last_applied_block = block_num;

        Ok(effects)
    }
}

/// Applies a committed block to the database and only then publishes the chain snapshot it
/// belongs to.
///
/// The snapshot must not become visible before its database state is durable. A failed write
/// leaves `chain` on the previous snapshot, so the next block is applied against the state the
/// database still holds.
async fn persist_and_publish_chain_state(
    db: &NtxDbWriter,
    chain: &mut ChainState,
    effects: CommittedBlockEffects,
    next_chain: ChainState,
) -> anyhow::Result<()> {
    let next_mmr = next_chain.current_mmr();
    db.apply_committed_block(effects, next_mmr)
        .await
        .context("failed to apply committed block to DB")?;
    *chain = next_chain;
    Ok(())
}

#[cfg(test)]
mod protocol_config_tests {
    use miden_protocol::crypto::merkle::mmr::PartialMmr;
    use miden_protocol::protocol_config::ProtocolConfig;

    use super::persist_and_publish_chain_state;
    use crate::chain_state::ChainState;
    use crate::committed_block::CommittedBlockEffects;
    use crate::db::test_setup;
    use crate::test_utils::{mock_block_header, mock_network_account_update};

    /// A failed database transaction must leave the published chain snapshot unchanged.
    #[tokio::test]
    async fn failed_database_write_does_not_publish_chain_snapshot() {
        let (db, _dir) = test_setup().await;
        let config = ProtocolConfig::mock();
        let mut chain =
            ChainState::new(mock_block_header(0_u32.into()), PartialMmr::default(), config);
        let next_header = mock_block_header(1_u32.into());
        let next = chain.next_tip_from_header(next_header.clone(), None, 4).unwrap();
        let (account, details) = mock_network_account_update();
        let effects = CommittedBlockEffects {
            header: next_header,
            network_notes: vec![],
            sponsorship_notes: vec![],
            nullifiers: vec![],
            network_account_updates: vec![(account.id(), details)],
            account_transactions: vec![],
        };

        persist_and_publish_chain_state(&db, &mut chain, effects, next)
            .await
            .expect_err("a post-genesis account update without a transaction must fail");

        assert_eq!(chain.chain_tip_header.block_num(), 0_u32.into());
    }
}
