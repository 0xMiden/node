use std::future::IntoFuture;
use std::time::Duration;

use anyhow::{Context, ensure};
use iroh::endpoint::{Connection, Incoming, Side};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use miden_node_tracing::warn;
use miden_node_utils::retry::{self, Retryable};
use miden_protocol::block::ValidatorConfig;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_validator::ValidatorSigner;
use rand_core_06::OsRng;

use super::super::wire::{RecvStream, SendStream};
use super::Ceremony;
use super::ceremony_config::CeremonyConfig;
use super::challenge::{Challenge, ChallengeResponse};
use super::completion::Completion;
use super::dkg::confirmation::DkgDealingsCommitment;
use super::dkg::{DealerMessages, DkgPublicKey, DkgRegistryRoot};
use super::session::{CeremonyNonce, SessionId};

pub struct ConnectedPeer {
    connection: Connection,
}

impl ConnectedPeer {
    /// Retries connection attempts with backoff until the peer connects or the endpoint closes.
    /// The caller must apply the ceremony timeout.
    ///
    /// Peers can start at different times. Authentication runs after this method returns and
    /// must not be retried.
    pub async fn connect(endpoint: &Endpoint, peer_addr: EndpointAddr) -> anyhow::Result<Self> {
        let peer_endpoint = peer_addr.id;
        let connection = (|| endpoint.connect(peer_addr.clone(), Ceremony::ALPN))
            .retry(retry::exponential(Duration::from_secs(1), Duration::from_secs(10)))
            .when(|_| !endpoint.is_closed())
            .notify(|error, delay| {
                warn!(
                    error,
                    target: miden_validator::LOG_TARGET,
                    "Retrying DKG peer connection",
                    dkg.peer.endpoint = peer_endpoint.to_string() #[nonstandard],
                    retry.delay_ms = delay.as_millis() as u64
                );
            })
            .await
            .with_context(|| format!("failed to connect to peer endpoint {peer_endpoint}"))?;
        Ok(Self { connection })
    }

    /// Establishes one incoming connection within ten seconds.
    ///
    /// The timeout releases capacity when a remote endpoint does not complete establishment.
    pub async fn accept(incoming: Incoming) -> anyhow::Result<Self> {
        let connection = tokio::time::timeout(Duration::from_secs(10), incoming.into_future())
            .await
            .context("incoming peer connection timed out")?
            .context("failed to establish incoming peer connection")?;
        Ok(Self { connection })
    }

    async fn bi_stream(&self) -> anyhow::Result<(SendStream, RecvStream)> {
        let (send, receive) = match self.connection.side() {
            Side::Client => {
                self.connection.open_bi().await.context("failed to open bidirectional stream")?
            },
            Side::Server => self
                .connection
                .accept_bi()
                .await
                .context("failed to accept bidirectional stream")?,
        };
        Ok((SendStream::from(send), RecvStream::from(receive)))
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.connection.remote_id()
    }

    pub fn close(self, reason: &[u8]) {
        self.connection.close(0u8.into(), reason);
    }

    pub async fn authenticate(
        self,
        validator_set: &ValidatorConfig,
        signer: &ValidatorSigner,
    ) -> anyhow::Result<AuthenticatedPeer> {
        let (mut send, mut receive) =
            self.bi_stream().await.context("failed to establish authentication stream")?;
        let challenge = Challenge::random(&mut OsRng);

        send.write(&challenge)
            .await
            .context("failed to send authentication challenge")?;

        let peer_challenge = receive
            .read_exact::<Challenge>(Challenge::BYTES)
            .await
            .context("failed to read authentication challenge")?;

        let response = peer_challenge.sign(signer).await?;
        send.write(&response).await.context("failed to send authentication response")?;

        let response = receive
            .read_exact::<ChallengeResponse>(ChallengeResponse::BYTES)
            .await
            .context("failed to read challenge response")?;
        let validator_public_key = response.verify_against(&challenge)?;
        ensure!(
            validator_set.keys().contains(&validator_public_key),
            "peer validator key is not committed by genesis",
        );
        Ok(AuthenticatedPeer {
            validator_public_key,
            connection: self,
            send,
            receive,
        })
    }
}

pub struct AuthenticatedPeer {
    validator_public_key: PublicKey,
    connection: ConnectedPeer,
    send: SendStream,
    receive: RecvStream,
}

impl AuthenticatedPeer {
    pub async fn exchange_ceremony_config(&mut self, local: &CeremonyConfig) -> anyhow::Result<()> {
        self.send.write(local).await.context("failed to send ceremony config")?;

        let peer_config = self
            .receive
            .read_exact::<CeremonyConfig>(CeremonyConfig::BYTES)
            .await
            .context("failed to read ceremony config")?;
        ensure!(
            &peer_config == local,
            "peer ceremony config does not match: local {local:?}, peer {peer_config:?}",
        );
        Ok(())
    }

    pub async fn exchange_ceremony_nonce(
        &mut self,
        local: &CeremonyNonce,
    ) -> anyhow::Result<CeremonyNonce> {
        self.send.write(local).await.context("failed to send ceremony nonce")?;
        let peer_nonce = self
            .receive
            .read_exact::<CeremonyNonce>(CeremonyNonce::BYTES)
            .await
            .context("failed to read ceremony nonce")?;
        Ok(peer_nonce)
    }

    pub async fn exchange_session_id(&mut self, local: &SessionId) -> anyhow::Result<SessionId> {
        self.send.write(local).await.context("failed to send session ID")?;
        let peer_session_id = self
            .receive
            .read_exact::<SessionId>(SessionId::BYTES)
            .await
            .context("failed to read session ID")?;
        Ok(peer_session_id)
    }

    pub async fn exchange_dkg_public_key(
        &mut self,
        local: &DkgPublicKey,
    ) -> anyhow::Result<DkgPublicKey> {
        self.send.write(local).await.context("failed to send DKG public key")?;
        let peer_dkg_public_key = self
            .receive
            .read_exact::<DkgPublicKey>(DkgPublicKey::BYTES)
            .await
            .context("failed to read DKG public key")?;
        Ok(peer_dkg_public_key)
    }

    pub async fn exchange_dkg_registry_root(
        &mut self,
        local: &DkgRegistryRoot,
    ) -> anyhow::Result<DkgRegistryRoot> {
        self.send.write(local).await.context("failed to send DKG registry root")?;
        let peer_registry_root = self
            .receive
            .read_exact::<DkgRegistryRoot>(DkgRegistryRoot::BYTES)
            .await
            .context("failed to read DKG registry root")?;
        Ok(peer_registry_root)
    }

    pub async fn exchange_dealer_messages(
        &mut self,
        local: &DealerMessages,
    ) -> anyhow::Result<DealerMessages> {
        let message_bytes =
            self.send.write(local).await.context("failed to send local dealer messages")?;
        let peer_messages = self
            .receive
            .read_exact::<DealerMessages>(message_bytes)
            .await
            .context("failed to read peer dealer messages")?;
        Ok(peer_messages)
    }

    pub async fn exchange_dealings_commitment(
        &mut self,
        local: &DkgDealingsCommitment,
    ) -> anyhow::Result<DkgDealingsCommitment> {
        self.send.write(local).await.context("failed to send DKG dealings commitment")?;
        let peer_commitment = self
            .receive
            .read_exact::<DkgDealingsCommitment>(DkgDealingsCommitment::BYTES)
            .await
            .context("failed to read DKG dealings commitment")?;
        Ok(peer_commitment)
    }

    pub async fn exchange_completion(&mut self, local: &Completion) -> anyhow::Result<Completion> {
        self.send.write(local).await.context("failed to send ceremony completion")?;
        self.send.finish()?;
        let peer_completion = self
            .receive
            .read_exact::<Completion>(Completion::BYTES)
            .await
            .context("failed to read peer ceremony completion")?;
        self.send.wait_for_delivery().await.with_context(|| {
            format!("failed to deliver ceremony completion to {}", self.connection.endpoint_id())
        })?;
        Ok(peer_completion)
    }

    pub fn validator_public_key(&self) -> &PublicKey {
        &self.validator_public_key
    }

    #[cfg(test)]
    pub fn connection(&self) -> &Connection {
        &self.connection.connection
    }

    #[cfg(test)]
    pub fn into_streams(
        self,
    ) -> (Connection, iroh::endpoint::SendStream, iroh::endpoint::RecvStream) {
        (self.connection.connection, self.send.into_inner(), self.receive.into_inner())
    }
}
