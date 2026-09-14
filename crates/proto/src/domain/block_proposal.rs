//! Shared decoding of block proposal fields.

use miden_protocol::batch::{OrderedBatches, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockInputs, ProposedBlock};

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
            miden_objects::conversion::decode_standalone_proven_batch(batch)
                .map_err(|error| ConversionError::from(error.context(format!("batches[{index}]"))))
        })
        .collect::<Result<Vec<ProvenBatch>, _>>()?;
    let next_validator_config = next_validator_config.try_into().map_err(ConversionError::from)?;
    let next_protocol_config = next_protocol_config
        .map(TryInto::try_into)
        .transpose()
        .map_err(ConversionError::from)?;
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
