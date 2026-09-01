use std::fmt;

use anyhow::{Context, ensure};
use golden_core::{GoldenGroup, GoldenScalar, ParticipantRegistry};
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_core_06::CryptoRngCore;

use super::super::wire::WireCodec;

pub type StorageGroup = Secp256k1GoldenGroup;
type StorageScalar = <StorageGroup as GoldenGroup>::Scalar;
type StorageElement = <StorageGroup as GoldenGroup>::Element;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgRegistryRoot([u8; 32]);

impl DkgRegistryRoot {
    pub fn from_registry(registry: &ParticipantRegistry<StorageGroup>) -> Self {
        Self(registry.root())
    }
}

impl WireCodec for DkgRegistryRoot {
    const BYTES: usize = 32;

    fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes = bytes.try_into().context("DKG registry root must contain exactly 32 bytes")?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for DkgRegistryRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

pub struct DkgSecretKey(StorageScalar);

impl DkgSecretKey {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        loop {
            let secret = StorageScalar::random(rng);
            if !bool::from(secret.is_zero()) {
                return Self(secret);
            }
        }
    }

    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey(StorageGroup::mul_generator(&self.0))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgPublicKey(StorageElement);

impl DkgPublicKey {
    pub fn into_element(self) -> StorageElement {
        self.0
    }
}

impl WireCodec for DkgPublicKey {
    const BYTES: usize = StorageGroup::ELEMENT_REPR_BYTES;

    fn encode(&self) -> Vec<u8> {
        StorageGroup::encode_element(&self.0).as_ref().to_vec()
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let encoded = bytes.try_into().context("DKG public key must contain exactly 33 bytes")?;
        let public_key =
            StorageGroup::decode_element(&encoded).context("failed to decode DKG public key")?;
        ensure!(
            !bool::from(StorageGroup::is_identity(&public_key)),
            "DKG public key must not be the group identity",
        );
        Ok(Self(public_key))
    }
}
