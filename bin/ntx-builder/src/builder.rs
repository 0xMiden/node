use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use futures::Stream;
use miden_node_tracing::{info, miden_instrument};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::protocol_config::ProtocolConfig;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use crate::actor::ActorRequest;
use crate::chain_state::{ChainState, SharedChainState};
use crate::clients::{BlockSubscriptionEvent, RpcError};
use crate::committed_block::CommittedBlockEffects;
use crate::coordinator::Coordinator;
use crate::db::NtxDbWriter;
use crate::server::NtxBuilderRpcServer;
use crate::{LOG_TARGET, NtxBuilderConfig};

/// Discriminator returned by the steady-state `select!` so the dispatch can run on a fully-owned
/// `&mut self` instead of three concurrent borrows. The `Block` variant is boxed since a
/// `SignedBlock` dwarfs the other two payloads.
enum SteadyStateAction {
    Block(Box<Option<Result<BlockSubscriptionEvent, RpcError>>>),
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
    Pin<Box<dyn Stream<Item = Result<BlockSubscriptionEvent, RpcError>> + Send>>;

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
    db: NtxDbWriter,
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
        db: NtxDbWriter,
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

        // Phase 2: spawn an actor for every account with carry-over pending notes. Accounts whose
        // creation has not been committed yet have their spawn deferred by the coordinator.
        let max_note_attempts = self.config.max_note_attempts;
        let pending_accounts = self
            .db
            .accounts_with_pending_notes(max_note_attempts)
            .await
            .context("failed to load accounts with pending notes at catch-up")?;
        info!(
            target: LOG_TARGET,
            "spawning actors for accounts with carry-over pending notes",
            account.ids.count = pending_accounts.len()
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
                    let (block, committed_tip, protocol_config) =
                        (*block).context("block stream ended")?.context("block stream failed")?;
                    let (effects, sponsored_accounts) = self
                        .apply_committed_block_with_effects(block, committed_tip, protocol_config)
                        .await?;
                    self.coordinator.handle_committed_block(&effects, &sponsored_accounts).await?;
                },
                SteadyStateAction::Request(request) => {
                    let Some(request) = request else {
                        anyhow::bail!("actor request channel closed unexpectedly");
                    };
                    handle_actor_request(&self.db, request, self.config.max_note_attempts).await?;
                },
                SteadyStateAction::Respawn(respawn) => {
                    if let Some(account_id) = respawn {
                        info!(
                            target: LOG_TARGET,
                            "respawning actor that shut down with a pending notification",
                            account.id = account_id
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

    /// Applies a committed block and returns the computed `CommittedBlockEffects`, plus the
    /// accounts whose pending feature notes gained a sponsorship in this block (one entry per
    /// sponsorship), so the steady-state loop can hand both to the coordinator without re-deriving
    /// them from the signed block.
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
    ) -> anyhow::Result<(CommittedBlockEffects, Vec<AccountId>)> {
        let header = block.header().clone();
        let block_num = header.block_num();

        let effects = CommittedBlockEffects::from_signed_block(&block);

        // Build the next immutable snapshot before persistence. Do not publish it until the
        // database transaction commits.
        let next_chain =
            self.chain
                .next_chain_tip(header, protocol_config, self.config.max_block_count)?;

        let effects_for_db = effects.clone();
        let sponsored_accounts =
            persist_and_publish_chain_state(&self.db, &self.chain, effects_for_db, next_chain)
                .await?;

        self.last_applied_block = block_num;

        Ok((effects, sponsored_accounts))
    }
}

async fn persist_and_publish_chain_state(
    db: &NtxDbWriter,
    chain: &SharedChainState,
    effects: CommittedBlockEffects,
    next_chain: ChainState,
) -> anyhow::Result<Vec<AccountId>> {
    let next_mmr = next_chain.current_mmr();
    let sponsored_accounts = db
        .apply_committed_block(effects, next_mmr)
        .await
        .context("failed to apply committed block to DB")?;
    chain.publish(next_chain);
    Ok(sponsored_accounts)
}

/// Handles a single actor request then acknowledges the actor. All writes go through the
/// framework's single writer connection, so the actors' reads cannot starve them.
async fn handle_actor_request(
    db: &NtxDbWriter,
    request: ActorRequest,
    max_note_attempts: usize,
) -> anyhow::Result<()> {
    match request {
        ActorRequest::NotesFailed { failed_notes, block_num, ack_tx } => {
            db.notes_failed(failed_notes, block_num)
                .await
                .context("failed to persist note failure")?;
            let _ = ack_tx.send(());
        },
        ActorRequest::NotesDiscarded { nullifiers, block_num, ack_tx } => {
            db.discard_notes(nullifiers, block_num, max_note_attempts)
                .await
                .context("failed to persist note discard")?;
            let _ = ack_tx.send(());
        },
        ActorRequest::CacheNoteScript { script_root, script } => {
            db.insert_note_scripts(script_root, script)
                .await
                .context("failed to cache note script")?;
        },
    }
    Ok(())
}

#[cfg(test)]
mod protocol_config_tests {
    use std::sync::Arc;

    use miden_protocol::crypto::merkle::mmr::PartialMmr;
    use miden_protocol::protocol_config::ProtocolConfig;

    use super::persist_and_publish_chain_state;
    use crate::chain_state::SharedChainState;
    use crate::committed_block::CommittedBlockEffects;
    use crate::db::test_setup;
    use crate::test_utils::{mock_block_header, mock_network_account_update};

    /// A failed database transaction must leave the published chain snapshot unchanged.
    #[tokio::test]
    async fn failed_database_write_does_not_publish_chain_snapshot() {
        let (db, _dir) = test_setup().await;
        let config = ProtocolConfig::mock();
        let chain = Arc::new(SharedChainState::new(
            mock_block_header(0_u32.into()),
            PartialMmr::default(),
            config,
        ));
        let next_header = mock_block_header(1_u32.into());
        let next = chain.next_chain_tip(next_header.clone(), None, 4).unwrap();
        let (account, details) = mock_network_account_update();
        let effects = CommittedBlockEffects {
            header: next_header,
            network_notes: vec![],
            sponsorship_notes: vec![],
            nullifiers: vec![],
            network_account_updates: vec![(account.id(), details)],
            account_transactions: vec![],
        };

        persist_and_publish_chain_state(&db, chain.as_ref(), effects, next)
            .await
            .expect_err("a post-genesis account update without a transaction must fail");

        assert_eq!(chain.get_cloned().chain_tip_header.block_num(), 0_u32.into());
    }
}
