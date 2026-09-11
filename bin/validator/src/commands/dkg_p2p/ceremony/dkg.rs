use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use anyhow::{Context, ensure};
use golden_core::wire::{from_wire_bytes, to_wire_bytes};
use golden_core::{
    DealerMessage,
    DkgConfig,
    DkgDealing,
    GoldenGroup,
    GoldenScalar,
    ParticipantIndex,
    ParticipantRegistry,
    SessionId as GoldenSessionId,
    create_dealing,
    create_dealing_with_secret,
    verify_dealing_for_receiver,
};
use golden_ehtdh1::derive_context_session_id;
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use miden_protocol::utils::serde::Serializable;
use rand_core_06::{CryptoRngCore, OsRng};

use self::confirmation::DkgDealingsCommitment;
use super::super::wire::WireCodec;
use super::{Ceremony, DkgParticipants};

mod completion;
pub mod confirmation;

#[cfg(test)]
mod tests;

pub type StorageGroup = Secp256k1GoldenGroup;
type StorageScalar = <StorageGroup as GoldenGroup>::Scalar;
type StorageElement = <StorageGroup as GoldenGroup>::Element;

pub struct LocalDealings {
    decryption_config: DkgConfig<StorageGroup>,
    decryption_dealing: DkgDealing<StorageGroup>,
    context_config: DkgConfig<StorageGroup>,
    context_dealing: DkgDealing<StorageGroup>,
}

pub struct UnconfirmedDkgDealings {
    local: LocalDealings,
    peer_decryption_dealings: BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    peer_context_dealings: BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
}

/// Verified dealings whose commitment matched every authenticated peer's commitment.
pub struct DkgDealings {
    local: LocalDealings,
    peer_decryption_dealings: BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    peer_context_dealings: BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    commitment: DkgDealingsCommitment,
}

#[derive(Clone)]
pub struct DealerMessages {
    decryption: DealerMessage<StorageGroup>,
    context: DealerMessage<StorageGroup>,
}

impl DealerMessages {
    const LENGTH_BYTES: usize = 8;

    fn from_local(dealings: &LocalDealings) -> Self {
        Self {
            decryption: dealings.decryption_dealing.message.clone(),
            context: dealings.context_dealing.message.clone(),
        }
    }

    fn encode_message(bytes: &mut Vec<u8>, message: &DealerMessage<StorageGroup>) {
        let message = to_wire_bytes(message);
        let length = u64::try_from(message.len()).expect("dealer message length must fit in u64");
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&message);
    }

    fn decode_message(
        bytes: &mut &[u8],
        round: &str,
    ) -> anyhow::Result<DealerMessage<StorageGroup>> {
        let length = bytes
            .get(..Self::LENGTH_BYTES)
            .with_context(|| format!("{round} dealer message is missing its length"))?;
        let length = u64::from_be_bytes(
            length.try_into().context("dealer message length must contain 8 bytes")?,
        );
        let length = usize::try_from(length).context("dealer message length does not fit usize")?;
        let remaining = &bytes[Self::LENGTH_BYTES..];
        let message = remaining
            .get(..length)
            .with_context(|| format!("{round} dealer message is shorter than its length"))?;
        *bytes = &remaining[length..];
        from_wire_bytes(message).with_context(|| format!("failed to decode {round} dealer message"))
    }
}

impl WireCodec for DealerMessages {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        Self::encode_message(&mut bytes, &self.decryption);
        Self::encode_message(&mut bytes, &self.context);
        bytes
    }

    fn decode(mut bytes: &[u8]) -> anyhow::Result<Self> {
        let decryption = Self::decode_message(&mut bytes, "decryption")?;
        let context = Self::decode_message(&mut bytes, "context")?;
        ensure!(bytes.is_empty(), "dealer messages contain trailing bytes");
        Ok(Self { decryption, context })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgRegistryRoot([u8; 32]);

impl DkgRegistryRoot {
    pub const BYTES: usize = 32;

    pub fn from_registry(registry: &ParticipantRegistry<StorageGroup>) -> Self {
        Self(registry.root())
    }
}

impl WireCodec for DkgRegistryRoot {
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

    pub fn create_dealings(&self, participants: &DkgParticipants) -> anyhow::Result<LocalDealings> {
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

        Ok(LocalDealings {
            decryption_config,
            decryption_dealing,
            context_config,
            context_dealing,
        })
    }

    pub async fn exchange_dealings(
        &self,
        participants: &DkgParticipants,
        local: LocalDealings,
    ) -> anyhow::Result<UnconfirmedDkgDealings> {
        let local_messages = Arc::new(DealerMessages::from_local(&local));
        let mut validator_keys = self.validator_set.as_keys().to_vec();
        validator_keys.sort_by_key(Serializable::to_bytes);

        let mut exchanges = tokio::task::JoinSet::new();
        for peer in participants.session.authenticated_peers.clone() {
            let position = validator_keys
                .iter()
                .position(|validator_key| validator_key == peer.validator_public_key())
                .context("authenticated peer is missing from the validator set")?;
            let dealer = ParticipantIndex::new(
                u32::try_from(position + 1).context("too many DKG participants")?,
            )?;
            let local_messages = Arc::clone(&local_messages);
            exchanges.spawn(async move {
                let messages = peer.exchange_dealer_messages(&local_messages).await?;
                Ok::<_, anyhow::Error>((dealer, messages))
            });
        }

        let mut peer_decryption_dealings = BTreeMap::new();
        let mut peer_context_dealings = BTreeMap::new();
        while let Some(result) = exchanges.join_next().await {
            let (dealer, messages) = result.context("dealing exchange task failed")??;
            ensure!(
                messages.decryption.dealer == dealer,
                "authenticated participant {} sent a decryption dealing for participant {}",
                dealer.get(),
                messages.decryption.dealer.get(),
            );
            ensure!(
                messages.context.dealer == dealer,
                "authenticated participant {} sent a context dealing for participant {}",
                dealer.get(),
                messages.context.dealer.get(),
            );
            verify_dealing_for_receiver::<StorageGroup, SecpSecqBackend>(
                participants.local_index,
                &participants.secret_key.0,
                &messages.decryption,
                &local.decryption_config,
            )
            .with_context(|| {
                format!("invalid decryption dealing from participant {}", dealer.get())
            })?;
            verify_dealing_for_receiver::<StorageGroup, SecpSecqBackend>(
                participants.local_index,
                &participants.secret_key.0,
                &messages.context,
                &local.context_config,
            )
            .with_context(|| {
                format!("invalid context dealing from participant {}", dealer.get())
            })?;
            ensure!(
                peer_decryption_dealings.insert(dealer, messages.decryption).is_none(),
                "received duplicate decryption dealing from participant {}",
                dealer.get(),
            );
            ensure!(
                peer_context_dealings.insert(dealer, messages.context).is_none(),
                "received duplicate context dealing from participant {}",
                dealer.get(),
            );
        }

        Ok(UnconfirmedDkgDealings {
            local,
            peer_decryption_dealings,
            peer_context_dealings,
        })
    }
}

impl LocalDealings {
    pub fn decryption_dealing_root(&self) -> [u8; 32] {
        self.decryption_dealing.message.transcript_root
    }

    pub fn context_dealing_root(&self) -> [u8; 32] {
        self.context_dealing.message.transcript_root
    }
}

impl DkgDealings {
    pub fn commitment(&self) -> DkgDealingsCommitment {
        self.commitment
    }

    pub fn decryption_dealing_count(&self) -> usize {
        std::iter::once(&self.local.decryption_dealing.message)
            .chain(self.peer_decryption_dealings.values())
            .count()
    }

    pub fn context_dealing_count(&self) -> usize {
        std::iter::once(&self.local.context_dealing.message)
            .chain(self.peer_context_dealings.values())
            .count()
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
    pub const BYTES: usize = StorageGroup::ELEMENT_REPR_BYTES;

    pub fn into_element(self) -> StorageElement {
        self.0
    }
}

impl WireCodec for DkgPublicKey {
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
