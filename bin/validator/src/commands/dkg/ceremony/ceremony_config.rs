use anyhow::{Context, ensure};
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_validator::StorageKeyEpoch;

use super::super::wire::WireCodec;

/// Shared ceremony parameters exchanged after peer authentication.
///
/// Decoding only checks the wire representation. The peer exchange requires equality with the
/// validated local configuration before the ceremony proceeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CeremonyConfig {
    validator_set_commitment: Word,
    threshold: u32,
    epoch: StorageKeyEpoch,
}

impl CeremonyConfig {
    pub const BYTES: usize = 32 + 4 + 32;

    /// Commits to the validator set independently of the order of CLI arguments.
    pub fn new(validator_keys: &[PublicKey], threshold: u32, epoch: StorageKeyEpoch) -> Self {
        let mut keys = validator_keys.iter().map(Serializable::to_bytes).collect::<Vec<_>>();
        keys.sort();
        let mut bytes = b"miden-validator-dkg-validator-set-v1".to_vec();
        for key in keys {
            bytes.extend_from_slice(&key);
        }
        let validator_set_commitment = Rpo256::hash(&bytes);
        Self {
            validator_set_commitment,
            threshold,
            epoch,
        }
    }
}

impl WireCodec for CeremonyConfig {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.validator_set_commitment.to_bytes();
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
            validator_set_commitment: Word::read_from_bytes(&bytes[..32])
                .context("failed to decode validator set commitment")?,
            threshold: u32::from_le_bytes(threshold),
            epoch: StorageKeyEpoch::new(epoch),
        })
    }
}
