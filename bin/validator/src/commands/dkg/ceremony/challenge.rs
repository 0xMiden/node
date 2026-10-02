use anyhow::{Context, ensure};
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_validator::ValidatorSigner;
use rand_core_06::CryptoRngCore;

use super::super::wire::WireCodec;

#[cfg(test)]
mod tests;

/// Fresh random bytes used to request proof of a peer's validator signing key on one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge([u8; 32]);

impl Challenge {
    pub const BYTES: usize = 32;
    const SIGNATURE_DOMAIN: &'static [u8] =
        b"miden-validator-dkg-p2p-peer-authentication-signature-v1";

    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Commits to the challenge and the TLS channel binding of the current Iroh connection.
    ///
    /// This prevents man-in-the-middle attacks that forward challenges and signed responses
    /// between separate connections. The binding must come from the local connection, not the peer.
    pub fn commitment(&self, channel_binding: &[u8; 32]) -> Word {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(Self::SIGNATURE_DOMAIN);
        transcript.extend_from_slice(channel_binding);
        transcript.extend_from_slice(&self.encode());
        Rpo256::hash(&transcript)
    }

    pub async fn sign(
        &self,
        signer: &ValidatorSigner,
        channel_binding: &[u8; 32],
    ) -> anyhow::Result<ChallengeResponse> {
        Ok(ChallengeResponse {
            validator_public_key: signer.public_key(),
            signature: signer.sign_commitment(self.commitment(channel_binding)).await?,
        })
    }
}

impl WireCodec for Challenge {
    fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes = bytes.try_into().context("challenge must contain exactly 32 bytes")?;
        Ok(Self(bytes))
    }
}

/// A claimed validator key and its signature over a challenge and connection binding. Decoding this
/// message does not authenticate the key or establish genesis membership.
#[derive(Debug)]
pub struct ChallengeResponse {
    validator_public_key: PublicKey,
    signature: Signature,
}

impl ChallengeResponse {
    pub const BYTES: usize = 33 + 65;

    /// Verifies proof of key ownership for the local challenge and connection binding.
    ///
    /// The returned key still requires a separate genesis membership check before it can identify
    /// an authenticated ceremony peer.
    pub fn verify_against(
        self,
        challenge: &Challenge,
        channel_binding: &[u8; 32],
    ) -> anyhow::Result<PublicKey> {
        ensure!(
            self.validator_public_key
                .verify(challenge.commitment(channel_binding), &self.signature),
            "peer challenge response signature is invalid",
        );
        Ok(self.validator_public_key)
    }
}

impl WireCodec for ChallengeResponse {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.validator_public_key.to_bytes();
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == Self::BYTES, "challenge response must contain 98 bytes");
        Ok(Self {
            validator_public_key: PublicKey::read_from_bytes(&bytes[..33])
                .context("failed to decode validator public key")?,
            signature: Signature::read_from_bytes(&bytes[33..])
                .context("failed to decode validator signature")?,
        })
    }
}
