use std::sync::{Arc, RwLock};

use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::transaction::PartialBlockchain;

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
}

impl ChainState {
    /// Constructs a new instance of [`ChainState`].
    pub(crate) fn new(chain_tip_header: BlockHeader, chain_mmr: PartialMmr) -> Self {
        let chain_mmr = PartialBlockchain::new(chain_mmr, [])
            .expect("partial blockchain should build from partial mmr");
        Self {
            chain_tip_header,
            chain_mmr: Arc::new(chain_mmr),
        }
    }

    /// Consumes the chain state and returns the chain tip header and the partial blockchain as a
    /// tuple.
    pub fn into_parts(self) -> (BlockHeader, Arc<PartialBlockchain>) {
        (self.chain_tip_header, self.chain_mmr)
    }

    /// Returns a clone of the current partial chain MMR.
    pub(crate) fn current_mmr(&self) -> PartialMmr {
        self.chain_mmr.mmr().clone()
    }

    /// Updates the chain tip and prunes old blocks from the MMR.
    pub(crate) fn update_chain_tip(&mut self, tip: BlockHeader, max_block_count: usize) {
        // Skip blocks already reflected in the chain state. The builder may load state during
        // startup before receiving the same block from the committed-block subscription.
        if tip.block_num() <= self.chain_tip_header.block_num() {
            tracing::debug!(
                event_block = %tip.block_num(),
                current_tip = %self.chain_tip_header.block_num(),
                "skipping committed block already reflected in chain state",
            );
            return;
        }

        // Update MMR which lags by one block.
        let mmr_tip = self.chain_tip_header.clone();
        Arc::make_mut(&mut self.chain_mmr).add_block(&mmr_tip, true);

        // Set the new tip.
        self.chain_tip_header = tip;

        // Keep MMR pruned.
        let pruned_block_height =
            (self.chain_mmr.chain_length().as_usize().saturating_sub(max_block_count)) as u32;
        Arc::make_mut(&mut self.chain_mmr).prune_to(..pruned_block_height.into());
    }
}

/// A thread-safe wrapper around [`ChainState`] that can be shared across multiple actors.
///
/// The API guarantees that the lock cannot be held across await points.
pub struct SharedChainState(RwLock<ChainState>);

impl SharedChainState {
    pub fn new(chain_tip_header: BlockHeader, chain_mmr: PartialMmr) -> Self {
        Self(RwLock::new(ChainState::new(chain_tip_header, chain_mmr)))
    }

    pub(crate) fn chain_tip_block_number(&self) -> BlockNumber {
        self.0.read().expect("chain state lock poisoned").chain_tip_header.block_num()
    }

    /// Returns a clone of the current partial chain MMR. Cheap enough for per-block persistence
    /// since the MMR is bounded by `max_block_count` headers.
    pub(crate) fn current_mmr(&self) -> PartialMmr {
        self.0.read().expect("chain state lock poisoned").current_mmr()
    }

    pub(crate) fn update_chain_tip(&self, tip: BlockHeader, max_block_count: usize) {
        self.0
            .write()
            .expect("chain state lock poisoned")
            .update_chain_tip(tip, max_block_count);
    }

    pub(crate) fn get_cloned(&self) -> ChainState {
        self.0.read().expect("chain state lock poisoned").clone()
    }
}
