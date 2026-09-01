use std::fmt;

use anyhow::{Context, ensure};
use golden_core::{
    DkgConfig,
    DkgDealing,
    GoldenGroup,
    GoldenScalar,
    ParticipantRegistry,
    SessionId as GoldenSessionId,
    create_dealing,
    create_dealing_with_secret,
};
use golden_ehtdh1::derive_context_session_id;
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_core_06::{CryptoRngCore, OsRng};

use super::super::wire::WireCodec;
use super::{Ceremony, DkgParticipants};

pub type StorageGroup = Secp256k1GoldenGroup;
type StorageScalar = <StorageGroup as GoldenGroup>::Scalar;
type StorageElement = <StorageGroup as GoldenGroup>::Element;

pub struct DkgDealings {
    decryption_dealing: DkgDealing<StorageGroup>,
    context_dealing: DkgDealing<StorageGroup>,
}

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

impl Ceremony {
    const DKG_BETA_DOMAIN: &'static [u8] = b"miden-storage-key-dkg-beta-v1";

    pub fn create_dealings(&self, participants: &DkgParticipants) -> anyhow::Result<DkgDealings> {
        let session_id = participants.session.id.encode();
        let session_id: [u8; 32] = session_id.try_into().map_err(|session_id: Vec<u8>| {
            anyhow::anyhow!("DKG session ID has {} bytes, expected 32", session_id.len())
        })?;
        let decryption_session_id = GoldenSessionId(session_id);
        let context_session_id = derive_context_session_id(decryption_session_id);
        let beta = StorageScalar::hash_to_scalar(
            Self::DKG_BETA_DOMAIN,
            StorageGroup::BACKEND_ID.as_bytes(),
        )
        .context("failed to derive storage key DKG beta")?;
        let threshold = self.threshold.get();
        let decryption_config =
            DkgConfig::new(threshold, decryption_session_id, beta, participants.registry.clone())
                .context("failed to build decryption DKG configuration")?;
        let context_config =
            DkgConfig::new(threshold, context_session_id, beta, participants.registry.clone())
                .context("failed to build context DKG configuration")?;

        let decryption_dealing = create_dealing::<StorageGroup, SecpSecqBackend>(
            participants.local_index,
            &participants.secret_key.0,
            &decryption_config,
            &mut OsRng,
        )
        .context("failed to create decryption dealing")?;
        let context_dealing = create_dealing_with_secret::<StorageGroup, SecpSecqBackend>(
            participants.local_index,
            &participants.secret_key.0,
            StorageScalar::zero(),
            &context_config,
            &mut OsRng,
        )
        .context("failed to create context dealing")?;

        Ok(DkgDealings { decryption_dealing, context_dealing })
    }
}

impl DkgDealings {
    pub fn decryption_dealing_root(&self) -> [u8; 32] {
        self.decryption_dealing.message.transcript_root
    }

    pub fn context_dealing_root(&self) -> [u8; 32] {
        self.context_dealing.message.transcript_root
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
