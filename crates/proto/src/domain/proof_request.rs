// PROOF REQUEST
// ================================================================================================

use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs};
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

pub struct BlockProofRequest {
    pub tx_batches: OrderedBatches,
    pub block_header: BlockHeader,
    pub block_inputs: BlockInputs,
}

impl Serializable for BlockProofRequest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { tx_batches, block_header, block_inputs } = self;
        tx_batches.write_into(target);
        block_header.write_into(target);
        block_inputs.write_into(target);
    }
}

impl Deserializable for BlockProofRequest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let block = Self {
            tx_batches: OrderedBatches::read_from(source)?,
            block_header: BlockHeader::read_from(source)?,
            block_inputs: BlockInputs::read_from(source)?,
        };

        Ok(block)
    }
}
