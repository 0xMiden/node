use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use futures::future::try_join_all;
use golden_core::{ParticipantIndex, ParticipantRegistry};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey as IrohSecretKey};
use miden_node_tracing::{info, warn};
use miden_node_utils::genesis::read_genesis_block;
use miden_protocol::Word;
use miden_protocol::block::ValidatorConfig;
use miden_protocol::utils::serde::Serializable;
use miden_validator::{StorageKeyEpoch, ValidatorSigner};
use rand_core_06::OsRng;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use zeroize::Zeroizing;

use self::ceremony_config::CeremonyConfig;
use self::dkg::{DkgRegistryRoot, DkgSecretKey, StorageGroup};
use self::peer::{AuthenticatedPeer, ConnectedPeer};
use self::session::{CeremonyNonce, SessionId};
use super::ParticipateOptions;

mod ceremony_config;
mod challenge;
pub mod completion;
mod dkg;
mod peer;
mod persistence;
mod session;
#[cfg(test)]
mod tests;

/// Peers whose distinct validator keys, together with the local key, match the genesis validator
/// set. Authentication alone does not establish agreement on ceremony configuration.
pub struct AuthenticatedPeers {
    authenticated_peers: Vec<AuthenticatedPeer>,
}

/// A session ID derived from the local configuration and every validator's nonce, before peers
/// confirm that they derived the same ID.
pub struct UnconfirmedSession {
    id: SessionId,
    authenticated_peers: Vec<AuthenticatedPeer>,
}

/// A session whose ID matches the ID reported by every authenticated peer.
pub struct Session {
    id: SessionId,
    authenticated_peers: Vec<AuthenticatedPeer>,
}

/// The local DKG secret and a registry built from authenticated validators' DKG public keys. Peer
/// agreement on the registry has not yet been checked.
pub struct UnconfirmedDkgParticipants {
    session: Session,
    local_index: ParticipantIndex,
    secret_key: DkgSecretKey,
    registry: ParticipantRegistry<StorageGroup>,
}

/// DKG participants whose registry root matches the root reported by every peer in the session. The
/// local secret corresponds to the public key registered at `local_index`.
pub struct DkgParticipants {
    session: Session,
    local_index: ParticipantIndex,
    secret_key: DkgSecretKey,
    registry: ParticipantRegistry<StorageGroup>,
}

/// Validated inputs for one live DKG ceremony. The genesis commitment and validator set come from
/// the same valid genesis block. The signer belongs to that set, and the nonzero threshold does
/// not exceed its size. The persistent endpoint identity is valid, with one distinct, non-local
/// peer endpoint per other genesis validator. Every peer has a direct socket address unless
/// public relays and address discovery are enabled.
///
/// These checks establish local configuration, not peer identities.
/// [`Ceremony::authenticate_peers`] must bind endpoints to genesis validator keys before the
/// ceremony exchanges configuration or DKG messages.
pub(super) struct Ceremony {
    genesis_commitment: Word,
    validator_set: Arc<ValidatorConfig>,
    endpoint_secret: IrohSecretKey,
    enable_public_relay: bool,
    bind_address: Option<SocketAddr>,
    peer_endpoints: BTreeMap<EndpointId, EndpointAddr>,
    threshold: NonZeroUsize,
    epoch: StorageKeyEpoch,
    signer: Arc<ValidatorSigner>,
}

impl Ceremony {
    const ALPN: &'static [u8] = b"/miden/validator-dkg-p2p/1";
    const MAX_PENDING_CONNECTIONS: usize = 16;

    /// Binds the persistent endpoint identity, opting into public infrastructure only when requested.
    ///
    /// An explicit bind address replaces both default wildcard listeners so a loopback bind stays
    /// local. The command handler owns endpoint shutdown.
    pub async fn bind_endpoint(&self) -> anyhow::Result<Endpoint> {
        let mut builder = Endpoint::builder(presets::Minimal);
        if self.enable_public_relay {
            builder = builder.preset(presets::N0);
        }
        if let Some(address) = self.bind_address {
            builder = builder.clear_ip_transports().bind_addr(address)?;
        }
        builder
            .secret_key(self.endpoint_secret.clone())
            .alpns(vec![Self::ALPN.to_vec()])
            .bind()
            .await
            .context("failed to bind Iroh endpoint")
    }

    /// Connects to every configured endpoint and requires exactly the genesis validator set.
    ///
    /// The smaller endpoint ID dials to avoid duplicate connections. Each connection authenticates
    /// independently, so a late peer does not block authentication of peers that are already online.
    pub async fn authenticate_peers(
        &self,
        endpoint: &Endpoint,
    ) -> anyhow::Result<AuthenticatedPeers> {
        let local_endpoint = endpoint.id();
        let mut authentications = JoinSet::new();
        for peer_addr in self.peer_endpoints.values().filter(|peer| local_endpoint < peer.id) {
            let peer_addr = peer_addr.clone();
            let endpoint = endpoint.clone();
            let validator_set = Arc::clone(&self.validator_set);
            let signer = Arc::clone(&self.signer);
            authentications.spawn(async move {
                ConnectedPeer::connect(&endpoint, peer_addr)
                    .await?
                    .authenticate(&validator_set, &signer)
                    .await
            });
        }

        let mut expected_incoming = self
            .peer_endpoints
            .keys()
            .copied()
            .filter(|peer| *peer < local_endpoint)
            .collect::<BTreeSet<_>>();
        let mut authenticated_peers = Vec::with_capacity(self.peer_endpoints.len());
        let mut progress = tokio::time::interval(Duration::from_secs(10));
        progress.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Establish incoming connections separately from validator authentication.
        //
        // These connections have no verified endpoint identity yet. Their failures must not
        // abort the ceremony, and slow connections must not block the accept loop.
        let mut incoming_connections = JoinSet::new();
        while !expected_incoming.is_empty() || !authentications.is_empty() {
            tokio::select! {
                incoming = endpoint.accept(), if !expected_incoming.is_empty() => {
                    let incoming = incoming.context("Iroh endpoint closed while waiting for a peer")?;
                    if incoming_connections.len() >= Self::MAX_PENDING_CONNECTIONS {
                        incoming.refuse();
                        continue;
                    }
                    incoming_connections.spawn(ConnectedPeer::accept(incoming));
                },
                Some(result) = incoming_connections.join_next() => {
                    let connected_peer = match result.context("incoming connection task failed")? {
                        Ok(peer) => peer,
                        Err(error) => {
                            warn!(
                                &error,
                                target: miden_validator::LOG_TARGET,
                                "Ignoring failed incoming DKG connection"
                            );
                            continue;
                        },
                    };
                    let peer_endpoint = connected_peer.endpoint_id();
                    if !self.peer_endpoints.contains_key(&peer_endpoint) {
                        connected_peer.close(b"endpoint is not a configured DKG peer");
                        continue;
                    }
                    if !expected_incoming.remove(&peer_endpoint) {
                        connected_peer.close(b"duplicate or wrong-direction DKG connection");
                        continue;
                    }
                    let validator_set = Arc::clone(&self.validator_set);
                    let signer = Arc::clone(&self.signer);
                    authentications.spawn(async move {
                        connected_peer.authenticate(&validator_set, &signer).await
                    });
                },
                Some(result) = authentications.join_next(), if !authentications.is_empty() => {
                    authenticated_peers.push(result.context("peer authentication task failed")??);
                },
                _ = progress.tick() => {
                    info!(
                        target: miden_validator::LOG_TARGET,
                        "Waiting for DKG peers to connect and authenticate",
                        dkg.peers.authenticated = authenticated_peers.len() #[nonstandard],
                        dkg.peers.expected = self.peer_endpoints.len() #[nonstandard]
                    );
                },
            }
        }

        // Check the complete validator set after individual proofs of key ownership.
        //
        // Membership checks alone would allow multiple endpoints to authenticate with one
        // validator's key while another genesis validator is absent.
        let mut authenticated_validator_keys = authenticated_peers
            .iter()
            .map(|peer| peer.validator_public_key().clone())
            .collect::<Vec<_>>();
        authenticated_validator_keys.push(self.signer.public_key());
        let authenticated_validator_set =
            ValidatorConfig::new(authenticated_validator_keys, self.validator_set.quorum())
                .context("authenticated validator keys do not form a valid validator set")?;
        ensure!(
            authenticated_validator_set == *self.validator_set,
            "authenticated validator set does not match genesis",
        );

        Ok(AuthenticatedPeers { authenticated_peers })
    }

    /// Requires each authenticated peer to use the same genesis commitment, threshold, and epoch
    /// before exchanging attempt-specific values.
    pub async fn exchange_configs(
        &self,
        mut peers: AuthenticatedPeers,
    ) -> anyhow::Result<AuthenticatedPeers> {
        let config = self.config()?;
        try_join_all(
            peers
                .authenticated_peers
                .iter_mut()
                .map(|peer| peer.exchange_ceremony_config(&config)),
        )
        .await?;

        Ok(peers)
    }

    /// Sends one fresh local nonce to every peer and derives the session ID from all contributions.
    ///
    /// Fresh nonces distinguish attempts even when the epoch, configuration, and persistent
    /// endpoint identities stay unchanged.
    pub async fn exchange_nonces(
        &self,
        mut peers: AuthenticatedPeers,
    ) -> anyhow::Result<UnconfirmedSession> {
        let config = self.config()?;
        let local_nonce = CeremonyNonce::random(&mut OsRng);
        let nonces = try_join_all(
            peers
                .authenticated_peers
                .iter_mut()
                .map(|peer| peer.exchange_ceremony_nonce(&local_nonce)),
        )
        .await?;

        let mut contributions = vec![(self.signer.public_key(), local_nonce)];
        for (peer, nonce) in peers.authenticated_peers.iter().zip(nonces) {
            contributions.push((peer.validator_public_key().clone(), nonce));
        }
        let id = SessionId::derive(&config, contributions);

        Ok(UnconfirmedSession {
            id,
            authenticated_peers: peers.authenticated_peers,
        })
    }

    /// Requires every peer to report the locally derived session ID before DKG key exchange.
    ///
    /// Comparing IDs detects a participant that sends different nonces to different validators.
    pub async fn confirm_session(
        &self,
        mut session: UnconfirmedSession,
    ) -> anyhow::Result<Session> {
        let id = session.id;
        try_join_all(session.authenticated_peers.iter_mut().map(|peer| async move {
            let peer_session_id = peer.exchange_session_id(&id).await?;
            ensure!(
                peer_session_id == id,
                "validator {:?} derived a different session ID: local {id}, peer {peer_session_id}",
                peer.validator_public_key(),
            );
            Ok::<_, anyhow::Error>(())
        }))
        .await?;

        Ok(Session {
            id,
            authenticated_peers: session.authenticated_peers,
        })
    }

    /// Generates the local DKG key and builds a registry from each validator's DKG public key.
    ///
    /// Indices start at one and follow validator signing-key byte order. Connection arrival order
    /// and endpoint IDs must not change which participant owns a share.
    pub async fn exchange_dkg_public_keys(
        &self,
        mut session: Session,
    ) -> anyhow::Result<UnconfirmedDkgParticipants> {
        let secret_key = DkgSecretKey::random(&mut OsRng);
        let local_dkg_public_key = secret_key.public_key();
        let mut dkg_public_keys =
            try_join_all(session.authenticated_peers.iter_mut().map(|peer| {
                let local_dkg_public_key = &local_dkg_public_key;
                async move {
                    let peer_dkg_public_key =
                        peer.exchange_dkg_public_key(local_dkg_public_key).await?;
                    Ok::<_, anyhow::Error>((
                        peer.validator_public_key().clone(),
                        peer_dkg_public_key,
                    ))
                }
            }))
            .await?;

        let local_validator_key = self.signer.public_key();
        dkg_public_keys.push((local_validator_key.clone(), local_dkg_public_key));
        dkg_public_keys.sort_by_key(|(validator_key, _)| validator_key.to_bytes());

        let mut local_index = None;
        let mut registry_entries = Vec::with_capacity(dkg_public_keys.len());
        for (offset, (validator_key, dkg_public_key)) in dkg_public_keys.into_iter().enumerate() {
            let index = ParticipantIndex::new(
                u32::try_from(offset + 1).context("too many DKG participants")?,
            )?;
            if validator_key == local_validator_key {
                local_index = Some(index);
            }
            registry_entries.push((index, dkg_public_key.into_element()));
        }
        let local_index =
            local_index.context("local validator is missing from DKG participants")?;
        let registry = ParticipantRegistry::new(registry_entries)
            .context("failed to build DKG participant registry")?;

        Ok(UnconfirmedDkgParticipants {
            session,
            local_index,
            secret_key,
            registry,
        })
    }

    /// Requires every peer to report the same participant indices and DKG public keys.
    ///
    /// A valid public key can still differ between recipients. Registry agreement is required
    /// before dealers encrypt contributions for those keys.
    pub async fn confirm_dkg_registry(
        &self,
        mut participants: UnconfirmedDkgParticipants,
    ) -> anyhow::Result<DkgParticipants> {
        let registry_root = DkgRegistryRoot::from_registry(&participants.registry);
        let confirmations = participants.session.authenticated_peers.iter_mut().map(|peer| async move {
            let peer_registry_root = peer.exchange_dkg_registry_root(&registry_root).await?;
            ensure!(
                peer_registry_root == registry_root,
                "validator {:?} built a different DKG registry: local {registry_root}, peer {peer_registry_root}",
                peer.validator_public_key(),
            );
            Ok::<_, anyhow::Error>(())
        });
        try_join_all(confirmations).await?;

        let UnconfirmedDkgParticipants {
            session,
            local_index,
            secret_key,
            registry,
        } = participants;
        Ok(DkgParticipants {
            session,
            local_index,
            secret_key,
            registry,
        })
    }

    fn config(&self) -> anyhow::Result<CeremonyConfig> {
        let threshold = u32::try_from(self.threshold.get())
            .context("threshold does not fit in the ceremony config format")?;
        Ok(CeremonyConfig::new(self.genesis_commitment, threshold, self.epoch))
    }
}

impl Session {
    pub fn id(&self) -> SessionId {
        self.id
    }
}

impl DkgParticipants {
    pub fn local_index(&self) -> ParticipantIndex {
        self.local_index
    }

    pub fn registry_root(&self) -> [u8; 32] {
        self.registry.root()
    }
}

impl ParticipateOptions {
    /// Loads trusted genesis and local key material and checks participation inputs before any peer
    /// connections are opened.
    pub(super) async fn validate(self) -> anyhow::Result<Ceremony> {
        let genesis =
            read_genesis_block(&self.genesis).context("failed to validate genesis block")?;
        let genesis_commitment = genesis.inner().header().commitment();
        let validator_set = genesis.inner().header().validator_config().clone();
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
        let peer_count = self.peer_endpoints.len();
        let peer_endpoints = self
            .peer_endpoints
            .into_iter()
            .map(|peer| (peer.id, peer))
            .collect::<BTreeMap<_, _>>();
        ensure!(peer_endpoints.len() == peer_count, "peer endpoints contain duplicates");
        ensure!(
            !peer_endpoints.contains_key(&endpoint_secret.public()),
            "peer endpoints contain the local endpoint",
        );
        for peer in peer_endpoints.values() {
            ensure!(
                self.enable_public_relay || peer.ip_addrs().next().is_some(),
                "peer {} requires a socket address unless --enable-public-relay is set",
                peer.id,
            );
        }

        let signer = Arc::new(self.signing_key.into_signer().await?);
        ensure!(
            validator_set.keys().contains(&signer.public_key()),
            "validator signing key is not committed by genesis",
        );

        Ok(Ceremony {
            genesis_commitment,
            validator_set: Arc::new(validator_set),
            endpoint_secret,
            enable_public_relay: self.enable_public_relay,
            bind_address: self.bind_address,
            peer_endpoints,
            threshold: self.threshold,
            epoch,
            signer,
        })
    }
}
