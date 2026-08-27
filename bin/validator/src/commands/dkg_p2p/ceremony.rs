use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::{Context, ensure};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId, SecretKey as IrohSecretKey};
use miden_node_store::genesis::GenesisBlock;
use miden_node_utils::genesis::read_genesis_block;
use miden_protocol::Word;
use miden_protocol::block::ValidatorKeys;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use miden_validator::{StorageKeyEpoch, ValidatorSigner};
use rand_core_06::{CryptoRngCore, OsRng};
use zeroize::Zeroizing;

use self::handshake::{AuthenticatedPeer, Handshake};
use super::ParticipateOptions;

mod handshake;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CeremonyNonce([u8; 32]);

impl CeremonyNonce {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        Self(nonce)
    }
}

impl Serializable for CeremonyNonce {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for CeremonyNonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_array()?))
    }
}

pub struct Session {
    endpoint: Endpoint,
    authenticated_peers: Vec<AuthenticatedPeer>,
}

/// Validated inputs for one peer-to-peer DKG ceremony.
///
/// # Invariants
///
/// - `genesis_commitment` and `validator_set` come from the same valid genesis block.
/// - `signer` is one of the validators committed by `validator_set`.
/// - `threshold` does not exceed the number of genesis validators.
/// - `endpoint_secret` is a valid persistent Iroh endpoint identity.
/// - `peer_endpoints` contains one distinct, non-local endpoint per other genesis validator.
///
/// Peer endpoints are not yet bound to individual validator keys. [`Ceremony::handshake`] performs
/// that authentication.
pub(super) struct Ceremony {
    genesis_commitment: Word,
    validator_set: ValidatorKeys,
    endpoint_secret: IrohSecretKey,
    peer_endpoints: BTreeSet<EndpointId>,
    threshold: NonZeroUsize,
    epoch: StorageKeyEpoch,
    signer: Arc<ValidatorSigner>,
}

impl Ceremony {
    pub async fn handshake(&self) -> anyhow::Result<Session> {
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(self.endpoint_secret.clone())
            .alpns(vec![Handshake::ALPN.to_vec()])
            .bind()
            .await
            .context("failed to bind Iroh endpoint")?;
        let nonce = CeremonyNonce::random(&mut OsRng);
        let threshold = u32::try_from(self.threshold.get())
            .context("threshold does not fit in the handshake format")?;
        let authenticated_peers = Handshake::new(
            self.genesis_commitment,
            threshold,
            self.epoch,
            nonce,
            self.validator_set.clone(),
            Arc::clone(&self.signer),
        )
        .connect_and_authenticate_peers(endpoint.clone(), self.peer_endpoints.clone())
        .await?;

        Ok(Session { endpoint, authenticated_peers })
    }
}

impl Session {
    pub async fn close(self) {
        for peer in self.authenticated_peers {
            peer.close();
        }
        self.endpoint.close().await;
    }
}

impl ParticipateOptions {
    pub(super) async fn validate(self) -> anyhow::Result<Ceremony> {
        let genesis = GenesisBlock::try_from(read_genesis_block(&self.genesis)?)
            .context("failed to validate genesis block")?;
        let genesis_commitment = genesis.inner().header().commitment();
        let validator_set = genesis.inner().header().validator_keys().clone();
        let validator_count = validator_set.len();

        ensure!(
            self.threshold.get() <= validator_count,
            "threshold must not exceed the {validator_count} genesis validators, got {}",
            self.threshold,
        );

        let epoch =
            StorageKeyEpoch::from_hex(self.epoch).context("failed to decode storage key epoch")?;

        let endpoint_secret_bytes =
            Zeroizing::new(fs_err::read(&self.endpoint_secret).with_context(|| {
                format!("failed to read Iroh endpoint secret {}", self.endpoint_secret.display())
            })?);
        let endpoint_secret = IrohSecretKey::try_from(endpoint_secret_bytes.as_slice())
            .context("failed to decode Iroh endpoint secret")?;

        let expected_peer_count = validator_count.saturating_sub(1);
        ensure!(
            self.peer_endpoints.len() == expected_peer_count,
            "expected {expected_peer_count} peer endpoints for {validator_count} genesis validators, got {}",
            self.peer_endpoints.len(),
        );
        let peer_endpoints = self.peer_endpoints.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            peer_endpoints.len() == self.peer_endpoints.len(),
            "peer endpoints contain duplicates",
        );
        ensure!(
            !peer_endpoints.contains(&endpoint_secret.public()),
            "peer endpoints contain the local endpoint",
        );

        let signer = Arc::new(self.signing_key.into_signer().await?);
        ensure!(
            validator_set.as_keys().contains(&signer.public_key()),
            "validator signing key is not committed by genesis",
        );

        Ok(Ceremony {
            genesis_commitment,
            validator_set,
            endpoint_secret,
            peer_endpoints,
            threshold: self.threshold,
            epoch,
            signer,
        })
    }
}
