use anyhow::{Context, ensure};
use miden_protocol::Word;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_validator::StorageKeyEpoch;

use super::super::wire::WireCodec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CeremonyConfig {
    genesis_commitment: Word,
    threshold: u32,
    epoch: StorageKeyEpoch,
}

impl CeremonyConfig {
    pub const BYTES: usize = 32 + 4 + 32;

    pub const fn new(genesis_commitment: Word, threshold: u32, epoch: StorageKeyEpoch) -> Self {
        Self { genesis_commitment, threshold, epoch }
    }
}

impl WireCodec for CeremonyConfig {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.genesis_commitment.to_bytes();
        bytes.extend_from_slice(&self.threshold.to_le_bytes());
        bytes.extend_from_slice(self.epoch.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == Self::BYTES, "ceremony config must contain 68 bytes");
        let threshold = bytes[32..36]
            .try_into()
            .context("ceremony config threshold must contain 4 bytes")?;
        let epoch =
            bytes[36..].try_into().context("ceremony config epoch must contain 32 bytes")?;
        Ok(Self {
            genesis_commitment: Word::read_from_bytes(&bytes[..32])
                .context("failed to decode genesis commitment")?,
            threshold: u32::from_le_bytes(threshold),
            epoch: StorageKeyEpoch::new(epoch),
        })
    }
}
