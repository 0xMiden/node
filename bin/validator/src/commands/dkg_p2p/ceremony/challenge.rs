use anyhow::ensure;
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use miden_validator::ValidatorSigner;
use rand_core_06::CryptoRngCore;

use super::super::wire::WireCodec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge([u8; 32]);

impl Challenge {
    const SIGNATURE_DOMAIN: &'static [u8] =
        b"miden-validator-dkg-p2p-peer-authentication-signature-v1";

    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn commitment(&self) -> Word {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(Self::SIGNATURE_DOMAIN);
        transcript.extend_from_slice(&self.to_bytes());
        Rpo256::hash(&transcript)
    }

    pub async fn sign(&self, signer: &ValidatorSigner) -> anyhow::Result<ChallengeResponse> {
        Ok(ChallengeResponse {
            validator_public_key: signer.public_key(),
            signature: signer.sign_commitment(self.commitment()).await?,
        })
    }
}

impl WireCodec for Challenge {
    const BYTES: usize = 32;
}

impl Serializable for Challenge {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for Challenge {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_array()?))
    }
}

#[derive(Debug)]
pub struct ChallengeResponse {
    validator_public_key: PublicKey,
    signature: Signature,
}

impl ChallengeResponse {
    pub fn verify_against(self, challenge: &Challenge) -> anyhow::Result<PublicKey> {
        ensure!(
            self.validator_public_key.verify(challenge.commitment(), &self.signature),
            "peer challenge response signature is invalid",
        );
        Ok(self.validator_public_key)
    }
}

impl WireCodec for ChallengeResponse {
    const BYTES: usize = 33 + 65;
}

impl Serializable for ChallengeResponse {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.validator_public_key.write_into(target);
        self.signature.write_into(target);
    }
}

impl Deserializable for ChallengeResponse {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            validator_public_key: PublicKey::read_from(source)?,
            signature: Signature::read_from(source)?,
        })
    }
}
