//! Thin-client state-fetch helpers used by `create_proofs::run`.
//!
//! These let the bench bind its proofs to the target node's actual chain
//! state (chain MMR at the tip) instead of fabricating an empty
//! `PartialBlockchain`. Without this, runs against any chain whose genesis
//! state isn't minimal (testnet, devnet, any local node restored from
//! a snapshot) fail with `AdviceError::MapKeyNotFound` during proof
//! generation.

use anyhow::{Context, Result};
use miden_node_proto::clients::RpcClient;
use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use miden_node_proto::generated::rpc::{FinalityLevel, SyncChainMmrRequest, SyncChainMmrResponse};
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::merkle::mmr::{MmrDelta, MmrPeaks, PartialMmr};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::PartialBlockchain;

/// Fetches and validates the complete transaction anchor for the committed chain tip.
pub(crate) async fn fetch_chain_tip_state(
    client: &mut RpcClient,
    genesis_header: &BlockHeader,
) -> Result<(BlockHeader, ProtocolConfig, PartialBlockchain)> {
    let response = client
        .sync_chain_mmr(SyncChainMmrRequest {
            current_client_block_height: 0,
            finality_level: FinalityLevel::Committed.into(),
        })
        .await
        .context("failed to call sync_chain_mmr")?
        .into_inner();

    decode_chain_tip_state(response, genesis_header)
}

fn decode_chain_tip_state(
    response: SyncChainMmrResponse,
    genesis_header: &BlockHeader,
) -> Result<(BlockHeader, ProtocolConfig, PartialBlockchain)> {
    let tip_header: BlockHeader = response
        .block_header
        .context("sync_chain_mmr response missing block_header")?
        .try_into()
        .context("failed to decode the chain tip block header")?;
    let protocol_config =
        ensure_protocol_config_is_present_and_matches_header(response.protocol_config, &tip_header)
            .context("sync_chain_mmr response missing a valid protocol configuration")?;
    let delta: MmrDelta = response
        .mmr_delta
        .context("sync_chain_mmr response missing mmr_delta")?
        .try_into()
        .context("failed to decode the chain MMR delta")?;

    let mut partial_mmr = PartialMmr::from_peaks(MmrPeaks::default());

    if tip_header.block_num().as_u32() != 0 {
        partial_mmr
            .add(genesis_header.commitment(), false)
            .context("failed to add the genesis commitment to the chain MMR")?;
        partial_mmr.apply(delta).context("failed to apply the chain MMR delta")?;
    }

    anyhow::ensure!(
        partial_mmr.peaks().hash_peaks() == tip_header.chain_commitment(),
        "synced MMR peaks do not match the chain commitment of block {}",
        tip_header.block_num(),
    );

    let blockchain = PartialBlockchain::new(partial_mmr, Vec::new())
        .context("failed to construct the partial blockchain")?;
    Ok((tip_header, protocol_config, blockchain))
}

#[cfg(test)]
mod tests {
    use miden_node_proto::generated::rpc::SyncChainMmrResponse;
    use miden_protocol::Word;
    use miden_protocol::account::AccountId;
    use miden_protocol::asset::AssetId;
    use miden_protocol::block::{BlockHeader, BlockNumber};
    use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrPeaks, PartialMmr};
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    };

    use super::decode_chain_tip_state;

    fn protocol_config(faucet: u128) -> ProtocolConfig {
        ProtocolConfig::current(AssetId::new_fungible(
            AccountId::try_from(faucet).expect("test faucet ID is valid"),
        ))
        .expect("test protocol configuration is valid")
    }

    fn header_with_config(
        template: &BlockHeader,
        block_num: BlockNumber,
        chain_commitment: Word,
        protocol_config: &ProtocolConfig,
    ) -> BlockHeader {
        BlockHeader::new(
            template.prev_block_commitment(),
            block_num,
            chain_commitment,
            template.account_root(),
            template.nullifier_root(),
            template.note_root(),
            template.tx_commitment(),
            template.validator_config().clone(),
            template.fee_parameters().clone(),
            protocol_config.to_commitment(),
            None,
            template.timestamp(),
        )
    }

    fn response(
        header: &BlockHeader,
        protocol_config: &ProtocolConfig,
        delta: MmrDelta,
    ) -> SyncChainMmrResponse {
        SyncChainMmrResponse {
            block_range: None,
            mmr_delta: Some(delta.into()),
            block_header: Some(header.into()),
            block_signatures: Vec::new(),
            protocol_config: Some(protocol_config.into()),
        }
    }

    #[test]
    fn chain_tip_response_rejects_mismatched_protocol_config() {
        let expected = protocol_config(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET);
        let other = protocol_config(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1);
        let template = BlockHeader::mock(0, None, None, &[]);
        let header = header_with_config(&template, BlockNumber::GENESIS, Word::empty(), &expected);
        let delta = MmrDelta {
            forest: Forest::new(0).expect("zero is a valid forest"),
            data: Vec::new(),
        };

        let error = decode_chain_tip_state(response(&header, &other, delta), &header)
            .expect_err("the response configuration must match its header");

        assert!(format!("{error:#}").contains("does not match header commitment"));
    }

    #[test]
    fn chain_tip_response_uses_changed_target_protocol_config() {
        let genesis_config = protocol_config(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET);
        let target_config = protocol_config(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1);
        let template = BlockHeader::mock(0, None, None, &[]);
        let genesis_header =
            header_with_config(&template, BlockNumber::GENESIS, Word::empty(), &genesis_config);
        let mut mmr = PartialMmr::from_peaks(MmrPeaks::default());
        mmr.add(genesis_header.commitment(), false).expect("the genesis leaf is valid");
        let target_header =
            header_with_config(&template, 1_u32.into(), mmr.peaks().hash_peaks(), &target_config);
        let delta = MmrDelta {
            forest: Forest::new(1).expect("one is a valid forest"),
            data: Vec::new(),
        };

        let (_, decoded, _) = decode_chain_tip_state(
            response(&target_header, &target_config, delta),
            &genesis_header,
        )
        .expect("the changed target configuration matches the target header");

        assert_eq!(decoded, target_config);
    }
}
