use miden_protocol::Word;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use miden_validator::StorageKeyEpoch;

use super::super::wire::WireCodec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CeremonyConfig {
    genesis_commitment: Word,
    threshold: u32,
    epoch: StorageKeyEpoch,
}

impl CeremonyConfig {
    pub const fn new(genesis_commitment: Word, threshold: u32, epoch: StorageKeyEpoch) -> Self {
        Self { genesis_commitment, threshold, epoch }
    }
}

impl WireCodec for CeremonyConfig {
    const BYTES: usize = 32 + 4 + 32;
}

impl Serializable for CeremonyConfig {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.genesis_commitment.write_into(target);
        target.write_u32(self.threshold);
        self.epoch.write_into(target);
    }
}

impl Deserializable for CeremonyConfig {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            genesis_commitment: Word::read_from(source)?,
            threshold: source.read_u32()?,
            epoch: StorageKeyEpoch::read_from(source)?,
        })
    }
}
