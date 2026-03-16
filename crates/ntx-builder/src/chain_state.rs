use std::sync::Arc;

use miden_protocol::block::BlockHeader;
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
}
