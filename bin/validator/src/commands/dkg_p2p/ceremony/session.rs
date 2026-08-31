use std::fmt;

use anyhow::Context;
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::Serializable;
use rand_core_06::CryptoRngCore;

use super::super::wire::WireCodec;
use super::ceremony_config::CeremonyConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeremonyNonce([u8; 32]);

impl CeremonyNonce {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl WireCodec for CeremonyNonce {
    const BYTES: usize = 32;

    fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes = bytes.try_into().context("ceremony nonce must contain exactly 32 bytes")?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(Word);

impl SessionId {
    const DOMAIN: &'static [u8] = b"miden-validator-dkg-p2p-session-id-v1";

    pub fn derive(
        config: &CeremonyConfig,
        mut contributions: Vec<(PublicKey, CeremonyNonce)>,
    ) -> Self {
        contributions.sort_by_key(|(validator_key, _)| validator_key.to_bytes());
        let mut transcript = Vec::new();
        transcript.extend_from_slice(Self::DOMAIN);
        transcript.extend_from_slice(&config.encode());
        for (validator_key, nonce) in contributions {
            transcript.extend_from_slice(&validator_key.to_bytes());
            transcript.extend_from_slice(&nonce.encode());
        }
        Self(Rpo256::hash(&transcript))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0.to_bytes()))
    }
}
