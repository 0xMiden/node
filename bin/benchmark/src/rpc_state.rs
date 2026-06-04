//! Thin-client state-fetch helpers used by `create_proofs::run`.
//!
//! These let the bench bind its proofs to the target node's actual chain
//! state (chain MMR at the tip) instead of fabricating an empty
//! `PartialBlockchain`. Without this, runs against any chain whose genesis
//! state isn't minimal (testnet, devnet, any local node restored from
//! a snapshot) fail with `AdviceError::MapKeyNotFound` during proof
//! generation.

use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::rpc::{
    BlockHeaderByNumberRequest,
    FinalityLevel,
    SyncChainMmrRequest,
};
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::merkle::mmr::{MmrDelta, MmrPeaks, PartialMmr};
use miden_protocol::transaction::PartialBlockchain;

/// Fetch the header of the latest committed block from the target node.
///
/// `get_block_header_by_number(block_num=None)` returns the chain tip per
/// the server's documented contract.
pub(crate) async fn fetch_chain_tip_header(client: &mut RpcClient) -> BlockHeader {
    let response = client
        .get_block_header_by_number(BlockHeaderByNumberRequest {
            block_num: None,
            include_mmr_proof: None,
        })
        .await
        .expect("failed to fetch chain tip header")
        .into_inner();

    response
        .block_header
        .expect("chain tip response missing block_header")
        .try_into()
        .expect("failed to decode chain tip block header")
}

/// Build a [`PartialBlockchain`] whose chain MMR matches the tip block's
/// `chain_commitment`.
///
/// Construction is:
///
/// - `tip_block_num == 0` → empty MMR (chain at genesis has no prior blocks committed). No RPC
///   calls.
/// - `tip_block_num >= 1` → MMR starts empty, then the genesis block's commitment is added as leaf
///   0 (this brings the local MMR's forest to 1, matching what the server expects as the caller's
///   pre-state for `block_from = 0`).
/// - `tip_block_num >= 2` → `sync_chain_mmr(block_from = 0, upper_bound = BlockNum(tip_block_num))`
///   is called and the returned `MmrDelta` is applied, bringing the MMR's forest from 1 up to
///   `tip_block_num`.
///
/// After this function returns, `partial_mmr.peaks().hash_peaks()` matches
/// the tip block's `chain_commitment()`.
pub(crate) async fn fetch_partial_blockchain(
    client: &mut RpcClient,
    tip_block_num: u32,
    genesis_header: &BlockHeader,
) -> PartialBlockchain {
    let mut partial_mmr = PartialMmr::from_peaks(MmrPeaks::default());

    if tip_block_num == 0 {
        return PartialBlockchain::new(partial_mmr, Vec::new())
            .expect("empty PartialBlockchain construction");
    }

    // Genesis is always leaf 0; this brings forest from 0 to 1.
    partial_mmr
        .add(genesis_header.commitment(), false)
        .expect("failed to add genesis commitment to partial MMR");

    if tip_block_num >= 2 {
        let request = SyncChainMmrRequest {
            current_client_block_height: 0,
            finality_level: FinalityLevel::Committed.into(),
        };

        let response = client
            .sync_chain_mmr(request)
            .await
            .expect("failed to call sync_chain_mmr")
            .into_inner();
        let mmr_delta_proto =
            response.mmr_delta.expect("sync_chain_mmr response missing mmr_delta");
        let mmr_delta: MmrDelta = mmr_delta_proto
            .try_into()
            .expect("failed to decode MmrDelta from sync_chain_mmr response");
        partial_mmr.apply(mmr_delta).expect("failed to apply chain MMR delta");
    }

    PartialBlockchain::new(partial_mmr, Vec::new())
        .expect("PartialBlockchain construction from fetched chain MMR")
}
