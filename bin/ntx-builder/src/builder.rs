use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use futures::Stream;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::block::{BlockNumber, SignedBlock};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::StreamExt;

use crate::NtxBuilderConfig;
use crate::actor::{AccountActorContext, ActorRequest};
use crate::chain_state::SharedChainState;
use crate::clients::StoreClient;
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
    /// Client for the store gRPC API.
    store: StoreClient,
    /// Database for persistent state.
    db: Db,
    /// Shared chain state updated by the event loop and read by actors.
    chain_state: Arc<SharedChainState>,
    /// Context shared with all account actors.
    actor_context: AccountActorContext,
    /// Stream of committed blocks from the store.
    block_stream: BlockStream,
    /// The chain tip the catch-up phase must reach before actors are spawned.
    catch_up_target: BlockNumber,
    /// Highest block number applied to the DB so far. Used during catch-up to decide when to
    /// stop draining the stream.
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
        store: StoreClient,
        db: Db,
        chain_state: Arc<SharedChainState>,
        actor_context: AccountActorContext,
        block_stream: BlockStream,
        catch_up_target: BlockNumber,
        last_applied_block: BlockNumber,
        actor_request_rx: mpsc::Receiver<ActorRequest>,
    ) -> Self {
        Self {
            config,
            coordinator,
            store,
            db,
            chain_state,
            actor_context,
            block_stream,
            catch_up_target,
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

        // Catch up to the chain tip before spawning any actors.
        self.catch_up().await?;

        join_set.spawn(self.run_event_loop());

        // Wait for either the event loop or the gRPC server to complete.
        // Any completion is treated as fatal.
        if let Some(result) = join_set.join_next().await {
            result.context("ntx-builder task panicked")??;
        }

        Ok(())
    }

    /// Drains the block stream until the synced block reaches the catch-up target.
    ///
    /// During this phase the coordinator does not spawn any actors: we just apply committed-state
    /// effects to the local DB and advance the shared chain state.
    async fn catch_up(&mut self) -> anyhow::Result<()> {
        let target = self.catch_up_target;

        if self.last_applied_block >= target {
            tracing::info!(
                current = %self.last_applied_block,
                %target,
                "ntx-builder already at or past chain tip"
            );
            return Ok(());
        }

        tracing::info!(
            current = %self.last_applied_block,
            %target,
            "ntx-builder catching up to chain tip before starting actors"
        );

        while self.last_applied_block < target {
            let block = self
                .block_stream
                .next()
                .await
                .context("block stream ended during catch-up")?
                .context("block stream failed during catch-up")?;
            self.apply_committed_block(block).await?;
        }

        tracing::info!(
            tip = %self.last_applied_block,
            "ntx-builder catch-up complete, starting actors"
        );

        Ok(())
    }

    /// Runs the main event loop.
    async fn run_event_loop(mut self) -> anyhow::Result<()> {
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
                // Handle account batches loaded from the store.
                // Once all accounts are loaded, the channel closes and this branch
                // becomes inactive (recv returns None and we stop matching).
                Some(account_id) = account_rx.recv() => {
                    self.handle_loaded_account(account_id).await?;
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

    /// Handles account IDs loaded from the store by syncing state to DB and spawning actors.
    #[tracing::instrument(name = "ntx.builder.handle_loaded_account", skip(self, account_id))]
    async fn handle_loaded_account(
        &mut self,
        account_id: NetworkAccountId,
    ) -> Result<(), anyhow::Error> {
        // Skip accounts already populated by the catch-up phase.
        if self
            .db
            .has_committed_account(account_id)
            .await
            .context("failed to check for committed account")?
        {
            self.coordinator.spawn_actor(account_id, &self.actor_context);
            return Ok(());
        }

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

        self.coordinator.spawn_actor(account_id, &self.actor_context);
        Ok(())
    }

    /// Handles a committed block from the live stream: applies effects, updates chain state, and
    /// notifies (and possibly respawns) affected actors.
    #[tracing::instrument(
        name = "ntx.builder.handle_committed_block",
        skip(self, block),
        fields(block.num = %block.header().block_num()),
    )]
    async fn handle_committed_block(&mut self, block: SignedBlock) -> Result<(), anyhow::Error> {
        let header = block.header().clone();
        let block_num = header.block_num();
        let effects = CommittedBlockEffects::from_signed_block(&block);
        let result = self
            .coordinator
            .apply_block(&effects)
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
        self.coordinator.notify_accounts(&result.accounts_to_notify);

        // Also notify every active actor so any actor currently waiting on its own submitted
        // transaction wakes up, even if its account wasn't touched by this block (e.g. tx was
        // dropped or expired without inclusion).
        self.coordinator.notify_all();

        Ok(())
    }

    /// Applies a committed block during the catch-up phase. Does not notify actors (there are
    /// none yet). The in-memory chain state is not touched during catch-up either, since it was
    /// initialized to the chain tip we are catching up to.
    async fn apply_committed_block(&mut self, block: SignedBlock) -> anyhow::Result<()> {
        let block_num = block.header().block_num();
        let effects = CommittedBlockEffects::from_signed_block(&block);
        self.coordinator
            .apply_block(&effects)
            .await
            .context("failed to apply committed block during catch-up")?;
        self.last_applied_block = block_num;
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use futures::stream;
    use miden_protocol::block::SignedBlock;
    use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};
    use url::Url;

    use super::*;
    use crate::NtxBuilderConfig;
    use crate::actor::AccountActorContext;
    use crate::clients::store::StoreError;
    use crate::test_utils::{mock_block_header, mock_signed_block};

    impl NetworkTransactionBuilder {
        /// Test-only accessor for `last_applied_block`.
        pub(crate) fn last_applied_block(&self) -> BlockNumber {
            self.last_applied_block
        }
    }

    /// Constructs a `NetworkTransactionBuilder` suitable for testing `catch_up`. Only the fields
    /// actually exercised during catch-up (`db`, `coordinator`, `chain_state`, `block_stream`,
    /// `catch_up_target`, `last_applied_block`) are populated with real values; everything else
    /// uses throwaway placeholders.
    async fn builder_for_catch_up_test(
        block_stream: BlockStream,
        catch_up_target: BlockNumber,
        last_applied_block: BlockNumber,
    ) -> (NetworkTransactionBuilder, tempfile::TempDir) {
        let (db, dir) = Db::test_setup().await;
        let url = Url::parse("http://127.0.0.1:1").unwrap();
        let config = NtxBuilderConfig::new(
            url.clone(),
            url.clone(),
            url.clone(),
            PathBuf::from("unused.sqlite3"),
        );
        let coordinator = Coordinator::new(4, 10, db.clone());
        let store = StoreClient::new(url);
        let chain_mmr = PartialMmr::from_peaks(MmrPeaks::new(Forest::new(0), vec![]).unwrap());
        let chain_state =
            Arc::new(SharedChainState::new(mock_block_header(0_u32.into()), chain_mmr));
        let actor_context = AccountActorContext::test(&db);
        let (_request_tx, actor_request_rx) = mpsc::channel(1);

        let builder = NetworkTransactionBuilder::new(
            config,
            coordinator,
            store,
            db,
            chain_state,
            actor_context,
            block_stream,
            catch_up_target,
            last_applied_block,
            actor_request_rx,
        );
        (builder, dir)
    }

    /// Builds a `BlockStream` from a sequence of `SignedBlock`s.
    fn ok_stream(blocks: Vec<SignedBlock>) -> BlockStream {
        Box::pin(stream::iter(blocks.into_iter().map(Ok::<_, StoreError>)))
    }

    #[tokio::test]
    async fn catch_up_returns_immediately_when_already_at_tip() {
        let target = BlockNumber::from(5u32);
        // No blocks: if catch_up tried to pull from the stream, it would error.
        let stream = ok_stream(vec![]);

        let (mut builder, _dir) = builder_for_catch_up_test(stream, target, target).await;
        builder.catch_up().await.expect("catch_up should no-op when already at tip");

        assert_eq!(builder.last_applied_block(), target);
    }

    #[tokio::test]
    async fn catch_up_drains_stream_to_target() {
        let target = BlockNumber::from(3u32);
        let blocks = vec![
            mock_signed_block(BlockNumber::from(1u32), &[], vec![]),
            mock_signed_block(BlockNumber::from(2u32), &[], vec![]),
            mock_signed_block(BlockNumber::from(3u32), &[], vec![]),
        ];
        let stream = ok_stream(blocks);

        let (mut builder, _dir) =
            builder_for_catch_up_test(stream, target, BlockNumber::from(0u32)).await;
        builder.catch_up().await.expect("catch_up should drain stream up to target");

        assert_eq!(builder.last_applied_block(), target);
    }

    #[tokio::test]
    async fn catch_up_errors_when_stream_ends_before_target() {
        let target = BlockNumber::from(3u32);
        // Stream yields only block 1, then ends.
        let stream = ok_stream(vec![mock_signed_block(BlockNumber::from(1u32), &[], vec![])]);

        let (mut builder, _dir) =
            builder_for_catch_up_test(stream, target, BlockNumber::from(0u32)).await;
        let err = builder.catch_up().await.expect_err("catch_up should fail when stream ends");

        assert!(
            format!("{err:#}").contains("block stream ended during catch-up"),
            "unexpected error message: {err:#}"
        );
        // The block that did arrive should still have been applied.
        assert_eq!(builder.last_applied_block(), BlockNumber::from(1u32));
    }

    #[tokio::test]
    async fn catch_up_propagates_stream_error() {
        let target = BlockNumber::from(2u32);
        // First item is an error; catch_up should surface it without applying anything.
        let stream: BlockStream = Box::pin(stream::iter(vec![Err::<SignedBlock, _>(
            StoreError::MalformedResponse("boom".into()),
        )]));

        let (mut builder, _dir) =
            builder_for_catch_up_test(stream, target, BlockNumber::from(0u32)).await;
        let err = builder.catch_up().await.expect_err("catch_up should propagate stream error");

        assert!(
            format!("{err:#}").contains("block stream failed during catch-up"),
            "unexpected error message: {err:#}"
        );
        assert_eq!(builder.last_applied_block(), BlockNumber::from(0u32));
    }
}
