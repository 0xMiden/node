use miden_protocol::Word;
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use rand_core_06::CryptoRngCore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge([u8; 32]);

impl Challenge {
    const SIGNATURE_DOMAIN: &'static [u8] = b"miden-validator-dkg-p2p-handshake-signature-v1";

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
