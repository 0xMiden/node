use anyhow::{Context, ensure};
use iroh::endpoint::{Connection, Side};
use iroh::{Endpoint, EndpointId};
use miden_protocol::block::ValidatorKeys;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_validator::ValidatorSigner;
use rand_core_06::OsRng;

use super::super::wire::{RecvStream, SendStream};
use super::Ceremony;
use super::ceremony_config::CeremonyConfig;
use super::challenge::{Challenge, ChallengeResponse};
use super::session::{CeremonyNonce, SessionId};

pub struct ConnectedPeer {
    connection: Connection,
}

impl ConnectedPeer {
    pub async fn connect(endpoint: &Endpoint, peer_endpoint: EndpointId) -> anyhow::Result<Self> {
        let connection = endpoint
            .connect(peer_endpoint, Ceremony::ALPN)
            .await
            .with_context(|| format!("failed to connect to peer endpoint {peer_endpoint}"))?;
        Ok(Self { connection })
    }

    pub async fn accept(endpoint: &Endpoint) -> anyhow::Result<Self> {
        let connection = endpoint
            .accept()
            .await
            .context("Iroh endpoint closed while waiting for a peer")?
            .await
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
        validator_set: &ValidatorKeys,
        signer: &ValidatorSigner,
    ) -> anyhow::Result<AuthenticatedPeer> {
        let (mut send, mut receive) =
            self.bi_stream().await.context("failed to establish authentication stream")?;
        let challenge = Challenge::random(&mut OsRng);

        send.write(&challenge)
            .await
            .context("failed to send authentication challenge")?;

        let peer_challenge = receive
            .read_exact::<Challenge>()
            .await
            .context("failed to read authentication challenge")?;

        let response = peer_challenge.sign(signer).await?;
        send.write(&response).await.context("failed to send authentication response")?;

        let response = receive
            .read_exact::<ChallengeResponse>()
            .await
            .context("failed to read challenge response")?;
        let validator_public_key = response.verify_against(&challenge)?;
        ensure!(
            validator_set.as_keys().contains(&validator_public_key),
            "peer validator key is not committed by genesis",
        );
        send.finish().context("failed to finish authentication stream")?;

        Ok(AuthenticatedPeer { validator_public_key, connection: self })
    }
}

pub struct AuthenticatedPeer {
    validator_public_key: PublicKey,
    connection: ConnectedPeer,
}

impl AuthenticatedPeer {
    pub async fn exchange_ceremony_config(&self, local: &CeremonyConfig) -> anyhow::Result<()> {
        let (mut send, mut receive) = self
            .connection
            .bi_stream()
            .await
            .context("failed to establish ceremony config stream")?;

        send.write(local).await.context("failed to send ceremony config")?;

        let peer_config = receive
            .read_exact::<CeremonyConfig>()
            .await
            .context("failed to read ceremony config")?;
        ensure!(
            &peer_config == local,
            "peer ceremony config does not match: local {local:?}, peer {peer_config:?}",
        );
        send.finish().context("failed to finish ceremony config stream")?;
        Ok(())
    }

    pub async fn exchange_ceremony_nonce(
        &self,
        local: &CeremonyNonce,
    ) -> anyhow::Result<CeremonyNonce> {
        let (mut send, mut receive) = self
            .connection
            .bi_stream()
            .await
            .context("failed to establish ceremony nonce stream")?;

        send.write(local).await.context("failed to send ceremony nonce")?;
        let peer_nonce = receive
            .read_exact::<CeremonyNonce>()
            .await
            .context("failed to read ceremony nonce")?;
        send.finish().context("failed to finish ceremony nonce stream")?;
        Ok(peer_nonce)
    }

    pub async fn exchange_session_id(&self, local: &SessionId) -> anyhow::Result<SessionId> {
        let (mut send, mut receive) = self
            .connection
            .bi_stream()
            .await
            .context("failed to establish session confirmation stream")?;

        send.write(local).await.context("failed to send session ID")?;
        let peer_session_id =
            receive.read_exact::<SessionId>().await.context("failed to read session ID")?;
        send.finish().context("failed to finish session confirmation stream")?;
        Ok(peer_session_id)
    }

    pub fn validator_public_key(&self) -> &PublicKey {
        &self.validator_public_key
    }

    #[cfg(test)]
    pub fn connection(&self) -> &Connection {
        &self.connection.connection
    }

    pub fn close(self) {
        self.connection.close(b"connection check complete");
    }
}
