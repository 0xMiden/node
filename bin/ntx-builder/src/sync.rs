//! Follows committed blocks and publishes chain snapshots after their database writes commit.

use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures::{Stream, StreamExt};
use miden_node_tracing::{debug, info, instrument, warn};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::protocol_config::ProtocolConfig;

use crate::chain_state::ChainState;
use crate::clients::{BlockSubscriptionEvent, RpcClient, RpcError};
use crate::committed_block::CommittedBlockEffects;
use crate::db::NtxDbWriter;

/// Boxed, pinned stream of committed blocks paired with the node-reported committed chain tip at
/// the time each block was emitted.
///
/// Boxing gives the stream a `'static` lifetime by ensuring it owns all its data, avoiding the
/// complex lifetime annotations otherwise required to store `impl Stream`.
pub(crate) type BlockStream =
    Pin<Box<dyn Stream<Item = Result<BlockSubscriptionEvent, RpcError>> + Send>>;

/// Tracks committed chain progress independently of transaction scheduling.
pub(crate) struct BlockFollower {
    stream: BlockStream,
    chain: ChainState,
    max_block_count: usize,
    /// Whether the follower has reached the upstream tip at least once.
    is_synced: bool,
}

impl BlockFollower {
    pub(crate) fn new(stream: BlockStream, chain: ChainState, max_block_count: usize) -> Self {
        Self {
            stream,
            chain,
            max_block_count,
            is_synced: false,
        }
    }

    pub(crate) fn chain(&self) -> &ChainState {
        &self.chain
    }

    pub(crate) fn is_synced(&self) -> bool {
        self.is_synced
    }

    pub(crate) async fn next_block(&mut self) -> anyhow::Result<BlockSubscriptionEvent> {
        self.stream
            .next()
            .await
            .context("block stream ended")?
            .context("block stream failed")
    }

    /// Applies a committed block before publishing its chain snapshot and reporting catch-up.
    #[instrument(name = "ntx.builder.apply_committed_block", fields(block.number = block.header().block_num(), tip.number = committed_tip))]
    pub(crate) async fn apply(
        &mut self,
        db: &NtxDbWriter,
        block: SignedBlock,
        committed_tip: BlockNumber,
        protocol_config: Option<ProtocolConfig>,
    ) -> anyhow::Result<CommittedBlockEffects> {
        let block_num = block.header().block_num();
        let next_chain =
            self.chain.next_chain_tip(&block, protocol_config, self.max_block_count)?;
        let effects = CommittedBlockEffects::from_signed_block(&block);
        persist_and_publish_chain_state(db, &mut self.chain, effects.clone(), next_chain).await?;
        if !self.is_synced && block_num == committed_tip {
            self.is_synced = true;
            info!("ntx-builder is now in sync", block.number = committed_tip);
        }
        Ok(effects)
    }
}

/// Delay between block-subscription reconnect attempts, paced so a node that immediately closes the
/// connection cannot spin the reconnect loop. Connection *failures* are already backed off
/// exponentially inside [`RpcClient::block_subscription_with_retry`].
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// How long a single `stream.next()` poll waits before re-evaluating liveness.
const BLOCK_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time without a committed block before treating the subscription as stalled and forcing a
/// reconnect.
///
/// This is a defensive backstop for a silently dropped connection that never surfaces an error on
/// its own (client HTTP/2 keepalive is the primary, faster detector). It must be comfortably larger
/// than the node's block interval so a legitimately quiet chain is not mistaken for a stall.
const STALL_TIMEOUT: Duration = Duration::from_mins(2);

/// Opens a committed-block subscription that transparently reconnects whenever the gRPC
/// connection is closed.
///
/// Each reconnection resumes from the block after the last one yielded, so no committed block
/// is skipped or replayed. A closed or errored subscription is logged and re-opened, paced by
/// the client's exponential backoff schedule.
pub(crate) fn reconnecting_blocks(
    client: RpcClient,
    block_from: BlockNumber,
) -> impl Stream<Item = Result<BlockSubscriptionEvent, RpcError>> + Send + 'static {
    debug!("ntx-builder opening committed-block subscription", block.from = block_from);
    futures::stream::unfold(
        (client, block_from, None, Instant::now()),
        |(client, mut next_from, mut inner, mut last_block)| async move {
            loop {
                // Open the subscription if we don't hold a live one. The connect itself retries
                // indefinitely with exponential backoff.
                let stream = match &mut inner {
                    Some(stream) => stream,
                    None => match client.block_subscription_with_retry(next_from).await {
                        Ok(stream) => {
                            info!("block subscription connected", block.from = next_from);
                            // Reset the stall clock so time spent (re)connecting is not counted
                            // against the next block's arrival.
                            last_block = Instant::now();
                            inner.insert(stream)
                        },
                        Err(err) => {
                            warn!(
                                &err,
                                "failed to open block subscription, retrying",
                                block.from = next_from
                            );
                            tokio::time::sleep(RECONNECT_DELAY).await;
                            continue;
                        },
                    },
                };

                // Poll on a short timeout so a silently dropped connection stays observable. Each
                // quiet poll emits a liveness log; once no block has arrived for `STALL_TIMEOUT`
                // the subscription is treated as stalled and reconnected.
                match tokio::time::timeout(BLOCK_POLL_TIMEOUT, stream.next()).await {
                    Ok(Some(Ok((block, committed_tip, protocol_config)))) => {
                        next_from = block.header().block_num().child();
                        last_block = Instant::now();
                        return Some((
                            Ok((block, committed_tip, protocol_config)),
                            (client, next_from, inner, last_block),
                        ));
                    },
                    Ok(Some(Err(err))) => warn!(
                        &err,
                        "block subscription failed, reconnecting",
                        block.from = next_from
                    ),
                    Ok(None) => warn!(
                        "block subscription closed by node, reconnecting",
                        block.from = next_from
                    ),
                    Err(_elapsed) => {
                        let idle = last_block.elapsed();
                        if idle < STALL_TIMEOUT {
                            // Quiet but not yet stalled: emit a liveness signal and keep polling
                            // the same stream instead of reconnecting.
                            debug!(
                                "no block received recently; subscription still open",
                                block.from = next_from,
                                subscription.idle_ms = idle.as_millis() as u64
                            );
                            continue;
                        }
                        warn!(
                            "no block received within stall timeout; treating subscription as stalled, reconnecting",
                            block.from = next_from,
                            subscription.idle_ms = idle.as_millis() as u64,
                            subscription.stall_timeout_ms = STALL_TIMEOUT.as_millis() as u64
                        );
                    },
                }

                // Reached on an error/close/stall branch: discard the stream, pace the reconnect,
                // and resume from the next un-applied block on the following iteration.
                inner = None;
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        },
    )
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
mod tests {
    use miden_protocol::crypto::merkle::mmr::PartialMmr;
    use miden_protocol::protocol_config::ProtocolConfig;

    use super::persist_and_publish_chain_state;
    use crate::chain_state::ChainState;
    use crate::committed_block::CommittedBlockEffects;
    use crate::db::queries::account_effect::NetworkAccountEffect;
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
            network_account_updates: vec![(
                account.id(),
                NetworkAccountEffect::from_account_creation(&details)
                    .expect("the mock account should be a network account"),
            )],
            account_transactions: vec![],
        };

        persist_and_publish_chain_state(&db, &mut chain, effects, next)
            .await
            .expect_err("a post-genesis account update without a transaction must fail");

        assert_eq!(chain.chain_tip_header.block_num(), 0_u32.into());
    }

    fn signed_child(
        chain: &ChainState,
        signer: &miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey,
    ) -> miden_protocol::block::SignedBlock {
        use std::collections::BTreeMap;

        use miden_protocol::block::{BlockInputs, BlockSignatures, ProposedBlock, SignedBlock};

        let parent = &chain.chain_tip_header;
        let inputs = BlockInputs::new(
            parent.clone(),
            chain.chain_mmr.as_ref().clone(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let (header, body) = ProposedBlock::new_at(inputs, vec![], parent.timestamp() + 1)
            .unwrap()
            .into_header_and_body()
            .unwrap();
        let signatures = BlockSignatures::new(vec![signer.sign(header.commitment())]).unwrap();
        SignedBlock::new_unchecked(header, body, signatures)
    }

    #[tokio::test]
    async fn block_follower_publishes_commits_and_only_marks_valid_catch_up() {
        use miden_node_store::GenesisState;
        use miden_node_utils::fee::{test_fee_params, test_protocol_config};
        use miden_protocol::block::{BlockSignatures, SignedBlock, ValidatorConfig};
        use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

        use super::BlockFollower;

        let (db, _dir) = test_setup().await;
        let signer = SigningKey::new();
        let config = test_protocol_config();
        let genesis = GenesisState::new(
            vec![],
            test_fee_params(),
            0,
            ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
            config.clone(),
        )
        .into_block()
        .unwrap();
        let header = genesis.inner().header().clone();
        db.insert_genesis_chain_state(header.clone(), header.commitment())
            .await
            .unwrap();
        let chain = ChainState::new(header, PartialMmr::default(), config);
        let mut follower = BlockFollower::new(Box::pin(futures::stream::empty()), chain, 4);
        let first = signed_child(follower.chain(), &signer);
        let unsigned = SignedBlock::new_unchecked(
            first.header().clone(),
            first.body().clone(),
            BlockSignatures::new(vec![]).unwrap(),
        );
        assert!(follower.apply(&db, unsigned, 1_u32.into(), None).await.is_err());
        assert!(!follower.is_synced());
        assert_eq!(follower.chain().chain_tip_header.block_num(), 0_u32.into());
        assert_eq!(db.select_chain_state().await.unwrap().unwrap().0, 0_u32.into());

        follower.apply(&db, first, 2_u32.into(), None).await.unwrap();
        assert!(!follower.is_synced());
        assert_eq!(follower.chain().chain_tip_header.block_num(), 1_u32.into());
        assert_eq!(db.select_chain_state().await.unwrap().unwrap().0, 1_u32.into());

        let second = signed_child(follower.chain(), &signer);
        follower.apply(&db, second, 2_u32.into(), None).await.unwrap();
        assert!(follower.is_synced());
        assert_eq!(db.select_chain_state().await.unwrap().unwrap().0, 2_u32.into());

        let third = signed_child(follower.chain(), &signer);
        follower.apply(&db, third, 5_u32.into(), None).await.unwrap();
        assert!(follower.is_synced());
        assert_eq!(follower.chain().chain_tip_header.block_num(), 3_u32.into());
        assert_eq!(db.select_chain_state().await.unwrap().unwrap().0, 3_u32.into());
    }
}
