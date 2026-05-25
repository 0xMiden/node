use std::pin::Pin;

use anyhow::Context;
use futures::Stream;
use miden_protocol::block::{BlockNumber, SignedBlock};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_stream::StreamExt;

use crate::NtxBuilderConfig;
use crate::chain_state::ChainState;
use crate::clients::StoreError;
use crate::committed_block::CommittedBlockEffects;
use crate::db::Db;
use crate::server::NtxBuilderRpcServer;

// NETWORK TRANSACTION BUILDER
// ================================================================================================

/// Boxed, pinned stream of committed blocks paired with the store-reported committed chain tip at
/// the time each block was emitted.
///
/// Boxing gives the stream a `'static` lifetime by ensuring it owns all its data, avoiding the
/// complex lifetime annotations otherwise required to store `impl Stream`.
pub(crate) type BlockStream =
    Pin<Box<dyn Stream<Item = Result<(SignedBlock, BlockNumber), StoreError>> + Send>>;

/// Network transaction builder component (PR 1: subscription-driven sync only).
///
/// The builder consumes the store's committed-block subscription and applies each block's
/// network-relevant effects to its local database. The actor execution path is wired back in a
/// subsequent PR; in this PR the binary stays up and keeps the local DB caught up to the live
/// chain tip without scheduling any network transactions.
pub struct NetworkTransactionBuilder {
    /// Configuration for the builder.
    config: NtxBuilderConfig,
    /// Database for persistent state.
    db: Db,
    /// Stream of committed blocks from the store.
    block_stream: BlockStream,
    /// Highest block number applied to the DB so far.
    last_applied_block: BlockNumber,
    /// In-memory partial chain (tip header + chain MMR + tracked recent headers). Persisted
    /// alongside each block in the DB so the builder can resume without replaying genesis on
    /// restart.
    chain: ChainState,
    /// `false` until the first applied block whose `committed_chain_tip` matches the just-applied
    /// block number. Stays `true` afterwards. Exposed so the gRPC status surface and PR 2's actor
    /// spawn gating can read it.
    is_synced: bool,
}

impl NetworkTransactionBuilder {
    pub(crate) fn new(
        config: NtxBuilderConfig,
        db: Db,
        block_stream: BlockStream,
        last_applied_block: BlockNumber,
        chain: ChainState,
    ) -> Self {
        Self {
            config,
            db,
            block_stream,
            last_applied_block,
            chain,
            is_synced: false,
        }
    }

    /// Returns `true` once the builder has caught up to the store's committed chain tip at least
    /// once. Stays `true` for the lifetime of the process.
    pub fn is_synced(&self) -> bool {
        self.is_synced
    }

    /// Runs the network transaction builder event loop until a fatal error occurs.
    ///
    /// 1. Starts the gRPC server for note status queries.
    /// 2. Continuously drains the committed-block subscription, applying each block's effects to
    ///    the local DB.
    pub async fn run(self, listener: TcpListener) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();

        // Start the gRPC server.
        let server = NtxBuilderRpcServer::new(self.db.clone(), self.config.max_note_attempts);
        join_set.spawn(async move {
            server.serve(listener).await.context("ntx-builder gRPC server failed")
        });

        join_set.spawn(self.run_event_loop());

        // Wait for either the event loop or the gRPC server to complete. Any completion is treated
        // as fatal.
        if let Some(result) = join_set.join_next().await {
            result.context("ntx-builder task panicked")??;
        }

        Ok(())
    }

    async fn run_event_loop(mut self) -> anyhow::Result<()> {
        // First sync up to the chain tip.
        loop {
            let (block, committed_tip) = self
                .block_stream
                .next()
                .await
                .context("block stream ended")?
                .context("block stream failed")?;
            let local_tip = block.header().block_num();
            self.apply_committed_block(block, committed_tip).await?;

            if local_tip == committed_tip {
                self.is_synced = true;
                tracing::info!(block.number = %committed_tip, "ntx-builder is now in sync");
                break;
            }
        }

        // Spawn and handle network account actors, and apply new blocks.
        loop {
            let (block, committed_tip) = self
                .block_stream
                .next()
                .await
                .context("block stream ended")?
                .context("block stream failed")?;
            self.apply_committed_block(block, committed_tip).await?;
        }
    }

    /// Applies a single committed block's effects to the DB, advances the in-memory partial chain,
    /// persists the updated chain MMR atomically with the effects, and flips `is_synced` the first
    /// time the applied block matches the store-reported committed tip.
    #[tracing::instrument(
        name = "ntx.builder.apply_committed_block",
        skip(self, block),
        fields(block_num = %block.header().block_num(), %committed_tip),
    )]
    async fn apply_committed_block(
        &mut self,
        block: SignedBlock,
        committed_tip: BlockNumber,
    ) -> anyhow::Result<()> {
        let header = block.header().clone();
        let block_num = header.block_num();

        let effects = CommittedBlockEffects::from_signed_block(&block);

        // Advance the in-memory chain (adds the previous tip header as an MMR leaf and prunes older
        // tracked headers) before snapshotting the MMR for persistence.
        self.chain.update_chain_tip(header, self.config.max_block_count);
        let next_mmr = self.chain.current_mmr();

        self.db
            .apply_committed_block(effects, next_mmr)
            .await
            .context("failed to apply committed block to DB")?;

        self.last_applied_block = block_num;

        Ok(())
    }
}
