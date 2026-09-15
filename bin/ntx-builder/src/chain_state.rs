use std::sync::{Arc, RwLock};

use miden_node_tracing::debug;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::PartialBlockchain;

use crate::LOG_TARGET;

// CHAIN STATE
// ================================================================================================

/// Contains information about the chain that is relevant to the [`NetworkTransactionBuilder`] and
/// all account actors managed by the [`Coordinator`].
///
/// The chain MMR stored here contains:
/// - The MMR peaks.
/// - Block headers and authentication paths for the last
///   [`NtxBuilderConfig::max_block_count`](crate::NtxBuilderConfig::max_block_count) blocks.
///
/// Authentication paths for older blocks are pruned because the NTX builder executes all notes as
/// "unauthenticated" (see [`InputNotes::from_unauthenticated_notes`]) and therefore does not need
/// to prove that input notes were created in specific past blocks.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// The current tip of the chain.
    pub chain_tip_header: BlockHeader,
    /// A partial representation of the chain MMR.
    ///
    /// Contains block headers and authentication paths for the last
    /// [`NtxBuilderConfig::max_block_count`](crate::NtxBuilderConfig::max_block_count) blocks
    /// only, since all notes are executed as unauthenticated.
    pub chain_mmr: Arc<PartialBlockchain>,
    /// The active protocol configuration for the chain tip.
    pub protocol_config: Arc<ProtocolConfig>,
}

impl ChainState {
    /// Constructs a new instance of [`ChainState`].
    pub(crate) fn new(
        chain_tip_header: BlockHeader,
        chain_mmr: PartialMmr,
        protocol_config: ProtocolConfig,
    ) -> Self {
        debug_assert_eq!(
            chain_tip_header.protocol_config_commitment(),
            protocol_config.to_commitment()
        );
        let chain_mmr = PartialBlockchain::new(chain_mmr, [])
            .expect("partial blockchain should build from partial mmr");
        Self {
            chain_tip_header,
            chain_mmr: Arc::new(chain_mmr),
            protocol_config: Arc::new(protocol_config),
        }
    }

    /// Consumes the chain state and returns its header, partial blockchain, and protocol config.
    pub fn into_parts(self) -> (BlockHeader, Arc<PartialBlockchain>, Arc<ProtocolConfig>) {
        (self.chain_tip_header, self.chain_mmr, self.protocol_config)
    }

    /// Returns a clone of the current partial chain MMR.
    pub(crate) fn current_mmr(&self) -> PartialMmr {
        self.chain_mmr.mmr().clone()
    }

    /// Builds the next chain snapshot and prunes old blocks from its MMR.
    pub(crate) fn next_chain_tip(
        &self,
        tip: BlockHeader,
        protocol_config: Option<ProtocolConfig>,
        max_block_count: usize,
    ) -> anyhow::Result<Self> {
        let next_config = if let Some(config) = protocol_config {
            anyhow::ensure!(
                config.to_commitment() == tip.protocol_config_commitment(),
                "block protocol config commitment does not match its header"
            );
            Arc::new(config)
        } else {
            anyhow::ensure!(
                self.protocol_config.to_commitment() == tip.protocol_config_commitment(),
                "committed block omitted a changed protocol config"
            );
            Arc::clone(&self.protocol_config)
        };

        // Skip blocks already reflected in the chain state. The builder may load state during
        // startup before receiving the same block from the committed-block subscription.
        if tip.block_num() <= self.chain_tip_header.block_num() {
            debug!(
                target: LOG_TARGET,
                "Skipping committed block already reflected in chain state",
                block.number = tip.block_num(),
                tip.number = self.chain_tip_header.block_num()
            );
            return Ok(self.clone());
        }

        let mut next = self.clone();
        next.protocol_config = next_config;

        // Update MMR which lags by one block.
        let mmr_tip = next.chain_tip_header.clone();
        Arc::make_mut(&mut next.chain_mmr).add_block(&mmr_tip, true);

        // Set the new tip.
        next.chain_tip_header = tip;

        // Keep MMR pruned.
        let pruned_block_height =
            (next.chain_mmr.chain_length().as_usize().saturating_sub(max_block_count)) as u32;
        Arc::make_mut(&mut next.chain_mmr).prune_to(..pruned_block_height.into());

        Ok(next)
    }
}

/// A thread-safe wrapper around [`ChainState`] that can be shared across multiple actors.
///
/// The API guarantees that the lock cannot be held across await points.
pub struct SharedChainState(RwLock<ChainState>);

impl SharedChainState {
    pub fn new(
        chain_tip_header: BlockHeader,
        chain_mmr: PartialMmr,
        protocol_config: ProtocolConfig,
    ) -> Self {
        Self(RwLock::new(ChainState::new(chain_tip_header, chain_mmr, protocol_config)))
    }

    pub(crate) fn chain_tip_block_number(&self) -> BlockNumber {
        self.0.read().expect("chain state lock poisoned").chain_tip_header.block_num()
    }

    pub(crate) fn next_chain_tip(
        &self,
        tip: BlockHeader,
        protocol_config: Option<ProtocolConfig>,
        max_block_count: usize,
    ) -> anyhow::Result<ChainState> {
        self.0.read().expect("chain state lock poisoned").next_chain_tip(
            tip,
            protocol_config,
            max_block_count,
        )
    }

    /// Publishes a snapshot after its database state is durable.
    pub(crate) fn publish(&self, next: ChainState) {
        *self.0.write().expect("chain state lock poisoned") = next;
    }

    pub(crate) fn get_cloned(&self) -> ChainState {
        self.0.read().expect("chain state lock poisoned").clone()
    }
}

#[cfg(test)]
mod protocol_config_tests {
    use miden_node_utils::fee::test_protocol_config;
    use miden_protocol::block::{BlockHeader, BlockNumber};
    use miden_protocol::crypto::merkle::mmr::PartialMmr;
    use miden_protocol::protocol_config::ProtocolConfig;

    use super::ChainState;
    use crate::test_utils::mock_block_header;

    fn other_protocol_config() -> ProtocolConfig {
        use miden_protocol::asset::AssetId;
        use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;

        ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
        ))
        .unwrap()
    }

    fn header_for_config(block_num: BlockNumber, config: &ProtocolConfig) -> BlockHeader {
        let header = mock_block_header(block_num);
        BlockHeader::new(
            header.prev_block_commitment(),
            header.block_num(),
            header.chain_commitment(),
            header.account_root(),
            header.nullifier_root(),
            header.note_root(),
            header.tx_commitment(),
            header.validator_config().clone(),
            header.fee_parameters().clone(),
            config.to_commitment(),
            header.next_protocol_config().cloned(),
            header.timestamp(),
        )
    }

    /// A transition creates a new snapshot and does not change an inflight old snapshot.
    #[test]
    fn next_tip_keeps_old_snapshot_immutable() {
        let config = test_protocol_config();
        let next_config = other_protocol_config();
        let old =
            ChainState::new(mock_block_header(0_u32.into()), PartialMmr::default(), config.clone());

        let next = old
            .next_chain_tip(
                header_for_config(1_u32.into(), &next_config),
                Some(next_config.clone()),
                4,
            )
            .expect("a matching changed config must create the next snapshot");

        assert_eq!(old.chain_tip_header.block_num(), 0_u32.into());
        assert_eq!(old.protocol_config.as_ref(), &config);
        assert_eq!(next.chain_tip_header.block_num(), 1_u32.into());
        assert_eq!(next.protocol_config.as_ref(), &next_config);
    }

    /// A missing changed configuration must not produce a next snapshot.
    #[test]
    fn next_tip_rejects_omitted_config_transition() {
        let config = test_protocol_config();
        let next_config = other_protocol_config();
        let old = ChainState::new(mock_block_header(0_u32.into()), PartialMmr::default(), config);
        let changed = header_for_config(1_u32.into(), &next_config);

        assert!(old.next_chain_tip(changed, None, 4).is_err());
        assert_eq!(old.chain_tip_header.block_num(), 0_u32.into());
    }
}
