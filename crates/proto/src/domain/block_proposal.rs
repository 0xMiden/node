//! Shared decoding of block proposal fields.

use miden_objects::{BuildUnchecked, DecodeMessage};
use miden_protocol::batch::{OrderedBatches, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockInputs, ProposedBlock};

use crate::decode::{verify_optional, verify_value};
use crate::errors::ConversionError;
use crate::generated as proto;

pub(super) struct DecodedBlockProposal {
    pub tx_batches: OrderedBatches,
    pub block_header: BlockHeader,
    pub block_inputs: BlockInputs,
}

pub(super) fn decode(
    block_inputs: proto::block_proving::BlockInputs,
    batches: Vec<proto::transaction::ProvenBatch>,
    timestamp: u32,
    next_validator_config: proto::blockchain::ValidatorConfig,
    next_protocol_config: Option<proto::blockchain::NextProtocolConfig>,
) -> Result<DecodedBlockProposal, ConversionError> {
    let block_inputs: BlockInputs = block_inputs.try_into()?;
    let batches = batches
        .into_iter()
        .enumerate()
        .map(|(index, batch)| {
            batch
                .decode_fields()
                .and_then(|batch| {
                    batch.build_unchecked().map_err(miden_objects::ConversionError::new)
                })
                .map_err(|error| ConversionError::from(error.context(format!("batches[{index}]"))))
        })
        .collect::<Result<Vec<ProvenBatch>, _>>()?;
    let next_validator_config = verify_value("next_validator_config", next_validator_config)?;
    let next_protocol_config = verify_optional("next_protocol_config", next_protocol_config)?;
    let proposed_block = ProposedBlock::new_at(block_inputs.clone(), batches.clone(), timestamp)
        .map_err(ConversionError::new)?
        .with_next_validator_config(next_validator_config)
        .with_next_protocol_config(next_protocol_config);
    let (block_header, _) = proposed_block.into_header_and_body().map_err(ConversionError::new)?;
    Ok(DecodedBlockProposal {
        tx_batches: OrderedBatches::new(batches),
        block_header,
        block_inputs,
    })
}
