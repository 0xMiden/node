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
use miden_validator::{StorageKeyEpoch, ValidatorSigner};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use self::ceremony_config::CeremonyConfig;
use self::peer::{AuthenticatedPeer, ConnectedPeer};
use super::ParticipateOptions;

mod ceremony_config;
mod challenge;
mod peer;
#[cfg(test)]
mod tests;

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
/// Peer endpoints are not yet bound to individual validator keys.
/// [`Ceremony::authenticate_peers`] performs that authentication.
pub(super) struct Ceremony {
    genesis_commitment: Word,
    validator_set: Arc<ValidatorKeys>,
    endpoint_secret: IrohSecretKey,
    peer_endpoints: BTreeSet<EndpointId>,
    threshold: NonZeroUsize,
    epoch: StorageKeyEpoch,
    signer: Arc<ValidatorSigner>,
}

impl Ceremony {
    const ALPN: &'static [u8] = b"/miden/validator-dkg-p2p/1";

    pub async fn authenticate_peers(&self) -> anyhow::Result<Session> {
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(self.endpoint_secret.clone())
            .alpns(vec![Self::ALPN.to_vec()])
            .bind()
            .await
            .context("failed to bind Iroh endpoint")?;
        self.authenticate_peers_on(endpoint).await
    }

    async fn authenticate_peers_on(&self, endpoint: Endpoint) -> anyhow::Result<Session> {
        let local_endpoint = endpoint.id();
        let mut authentications = JoinSet::new();
        for peer_endpoint in
            self.peer_endpoints.iter().copied().filter(|peer| local_endpoint < *peer)
        {
            let endpoint = endpoint.clone();
            let validator_set = Arc::clone(&self.validator_set);
            let signer = Arc::clone(&self.signer);
            authentications.spawn(async move {
                ConnectedPeer::connect(&endpoint, peer_endpoint)
                    .await?
                    .authenticate(&validator_set, &signer)
                    .await
            });
        }

        let mut expected_incoming = self
            .peer_endpoints
            .iter()
            .copied()
            .filter(|peer| *peer < local_endpoint)
            .collect::<BTreeSet<_>>();
        while !expected_incoming.is_empty() {
            let connected_peer = ConnectedPeer::accept(&endpoint).await?;
            let peer_endpoint = connected_peer.endpoint_id();
            if !self.peer_endpoints.contains(&peer_endpoint) {
                connected_peer.close(b"endpoint is not a configured DKG peer");
                continue;
            }
            ensure!(
                expected_incoming.remove(&peer_endpoint),
                "unexpected connection from peer endpoint {peer_endpoint}",
            );
            let validator_set = Arc::clone(&self.validator_set);
            let signer = Arc::clone(&self.signer);
            authentications
                .spawn(async move { connected_peer.authenticate(&validator_set, &signer).await });
        }

        let mut authenticated_peers = Vec::with_capacity(self.peer_endpoints.len());
        while let Some(result) = authentications.join_next().await {
            authenticated_peers.push(result.context("peer authentication task failed")??);
        }

        let mut authenticated_validator_keys = authenticated_peers
            .iter()
            .map(|peer| peer.validator_public_key().clone())
            .collect::<Vec<_>>();
        authenticated_validator_keys.push(self.signer.public_key());
        let authenticated_validator_set = ValidatorKeys::new(authenticated_validator_keys)
            .context("authenticated validator keys do not form a valid validator set")?;
        ensure!(
            authenticated_validator_set == *self.validator_set,
            "authenticated validator set does not match genesis",
        );

        Ok(Session { endpoint, authenticated_peers })
    }

    pub async fn exchange_configs(&self, session: Session) -> anyhow::Result<Session> {
        let threshold = u32::try_from(self.threshold.get())
            .context("threshold does not fit in the ceremony config format")?;
        let config = CeremonyConfig::new(self.genesis_commitment, threshold, self.epoch);
        let Session { endpoint, authenticated_peers } = session;
        let peer_count = authenticated_peers.len();
        let mut exchanges = JoinSet::new();
        for peer in authenticated_peers {
            let config = config.clone();
            exchanges.spawn(async move {
                peer.exchange_ceremony_config(&config).await?;
                Ok::<_, anyhow::Error>(peer)
            });
        }

        let mut authenticated_peers = Vec::with_capacity(peer_count);
        while let Some(result) = exchanges.join_next().await {
            authenticated_peers.push(result.context("ceremony config exchange task failed")??);
        }

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
            validator_set: Arc::new(validator_set),
            endpoint_secret,
            peer_endpoints,
            threshold: self.threshold,
            epoch,
            signer,
        })
    }
}
