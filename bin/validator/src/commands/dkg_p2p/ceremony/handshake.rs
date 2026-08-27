use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, ensure};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use miden_protocol::Word;
use miden_protocol::block::ValidatorKeys;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use miden_validator::{StorageKeyEpoch, ValidatorSigner};
use tokio::task::JoinSet;

use super::CeremonyNonce;

#[cfg(test)]
mod tests;

const HANDSHAKE_SIGNATURE_DOMAIN: &[u8] = b"miden-validator-dkg-p2p-handshake-signature-v1";
const HANDSHAKE_MESSAGE_BYTES: usize = 32 + 4 + 32 + 33 + 32;
const VALIDATOR_SIGNATURE_BYTES: usize = 65;

#[derive(Clone, Debug, Eq, PartialEq)]
struct HandshakeMessage {
    genesis_commitment: Word,
    threshold: u32,
    epoch: StorageKeyEpoch,
    validator_public_key: PublicKey,
    nonce: CeremonyNonce,
}

impl HandshakeMessage {
    fn validate_peer_configuration(&self, peer: &Self) -> anyhow::Result<()> {
        ensure!(
            self.genesis_commitment == peer.genesis_commitment,
            "peer genesis commitment does not match",
        );
        ensure!(self.threshold == peer.threshold, "peer threshold does not match");
        ensure!(self.epoch == peer.epoch, "peer storage key epoch does not match");
        Ok(())
    }
}

impl Serializable for HandshakeMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.genesis_commitment.write_into(target);
        target.write_u32(self.threshold);
        self.epoch.write_into(target);
        self.validator_public_key.write_into(target);
        self.nonce.write_into(target);
    }
}

impl Deserializable for HandshakeMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            genesis_commitment: Word::read_from(source)?,
            threshold: source.read_u32()?,
            epoch: StorageKeyEpoch::read_from(source)?,
            validator_public_key: PublicKey::read_from(source)?,
            nonce: CeremonyNonce::read_from(source)?,
        })
    }
}

struct HandshakeTranscript {
    dialer_endpoint: EndpointId,
    dialer_message: HandshakeMessage,
    acceptor_endpoint: EndpointId,
    acceptor_message: HandshakeMessage,
}

impl HandshakeTranscript {
    fn new(
        local_endpoint: EndpointId,
        local_message: HandshakeMessage,
        peer_endpoint: EndpointId,
        peer_message: HandshakeMessage,
    ) -> Self {
        if local_endpoint < peer_endpoint {
            Self {
                dialer_endpoint: local_endpoint,
                dialer_message: local_message,
                acceptor_endpoint: peer_endpoint,
                acceptor_message: peer_message,
            }
        } else {
            Self {
                dialer_endpoint: peer_endpoint,
                dialer_message: peer_message,
                acceptor_endpoint: local_endpoint,
                acceptor_message: local_message,
            }
        }
    }

    fn signature_commitment(&self) -> Word {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(HANDSHAKE_SIGNATURE_DOMAIN);
        transcript.extend_from_slice(self.dialer_endpoint.as_bytes());
        transcript.extend_from_slice(&self.dialer_message.to_bytes());
        transcript.extend_from_slice(self.acceptor_endpoint.as_bytes());
        transcript.extend_from_slice(&self.acceptor_message.to_bytes());
        Rpo256::hash(&transcript)
    }
}

#[derive(Clone)]
pub struct Handshake {
    message: HandshakeMessage,
    validator_set: Arc<ValidatorKeys>,
    signer: Arc<ValidatorSigner>,
}

impl Handshake {
    pub const ALPN: &'static [u8] = b"/miden/validator-dkg-p2p/1";

    pub fn new(
        genesis_commitment: Word,
        threshold: u32,
        epoch: StorageKeyEpoch,
        nonce: CeremonyNonce,
        validator_set: ValidatorKeys,
        signer: Arc<ValidatorSigner>,
    ) -> Self {
        let validator_public_key = signer.public_key();

        Self {
            message: HandshakeMessage {
                genesis_commitment,
                threshold,
                epoch,
                validator_public_key,
                nonce,
            },
            validator_set: Arc::new(validator_set),
            signer,
        }
    }

    pub async fn connect_and_authenticate_peers(
        self,
        endpoint: Endpoint,
        peer_endpoints: BTreeSet<EndpointId>,
    ) -> anyhow::Result<Vec<AuthenticatedPeer>> {
        let local_endpoint = endpoint.id();
        let mut dialed_peers = JoinSet::new();
        for peer_endpoint in peer_endpoints.iter().copied().filter(|peer| local_endpoint < *peer) {
            let endpoint = endpoint.clone();
            let handshake = self.clone();
            dialed_peers.spawn(async move {
                let connection =
                    endpoint.connect(peer_endpoint, Self::ALPN).await.with_context(|| {
                        format!("failed to connect to peer endpoint {peer_endpoint}")
                    })?;
                handshake.authenticate(connection, local_endpoint).await
            });
        }

        let mut expected_dialers = peer_endpoints
            .iter()
            .copied()
            .filter(|peer| *peer < local_endpoint)
            .collect::<BTreeSet<_>>();
        let mut authenticated = Vec::with_capacity(peer_endpoints.len());
        while !expected_dialers.is_empty() {
            let incoming = endpoint
                .accept()
                .await
                .context("Iroh endpoint closed while waiting for a peer")?;
            let connection = incoming
                .accept()
                .context("failed to accept peer connection")?
                .await
                .context("failed to establish incoming peer connection")?;
            let peer_endpoint = connection.remote_id();
            ensure!(
                expected_dialers.remove(&peer_endpoint),
                "unexpected connection from peer endpoint {}",
                peer_endpoint,
            );
            authenticated.push(self.clone().authenticate(connection, local_endpoint).await?);
        }

        while let Some(result) = dialed_peers.join_next().await {
            authenticated.push(result.context("peer authentication task failed")??);
        }
        authenticated.sort_by_key(AuthenticatedPeer::endpoint_id);
        let mut authenticated_validator_keys = authenticated
            .iter()
            .map(|peer| peer.validator_public_key.clone())
            .collect::<Vec<_>>();
        authenticated_validator_keys.push(self.message.validator_public_key.clone());
        let authenticated_validator_set = ValidatorKeys::new(authenticated_validator_keys)
            .context("authenticated validator keys do not form a valid validator set")?;
        ensure!(
            authenticated_validator_set == *self.validator_set,
            "authenticated validator set does not match genesis",
        );
        Ok(authenticated)
    }

    async fn authenticate(
        self,
        connection: Connection,
        local_endpoint: EndpointId,
    ) -> anyhow::Result<AuthenticatedPeer> {
        let peer_endpoint = connection.remote_id();
        let (mut send, mut receive) = if local_endpoint < peer_endpoint {
            connection.open_bi().await.context("failed to open handshake stream")?
        } else {
            connection.accept_bi().await.context("failed to accept handshake stream")?
        };
        let Handshake { message, signer, .. } = self;

        send.write_all(&message.to_bytes())
            .await
            .context("failed to send handshake message")?;
        let mut peer_message_bytes = [0; HANDSHAKE_MESSAGE_BYTES];
        receive
            .read_exact(&mut peer_message_bytes)
            .await
            .context("failed to read handshake message")?;
        let peer_message = HandshakeMessage::read_from_bytes(&peer_message_bytes)
            .context("failed to decode handshake message")?;
        message.validate_peer_configuration(&peer_message)?;

        let peer_validator_public_key = peer_message.validator_public_key.clone();
        let commitment =
            HandshakeTranscript::new(local_endpoint, message, peer_endpoint, peer_message)
                .signature_commitment();
        let signature = signer.sign_commitment(commitment).await?;
        send.write_all(&signature.to_bytes())
            .await
            .context("failed to send handshake signature")?;
        send.finish().context("failed to finish handshake stream")?;

        let mut peer_signature_bytes = [0; VALIDATOR_SIGNATURE_BYTES];
        receive
            .read_exact(&mut peer_signature_bytes)
            .await
            .context("failed to read handshake signature")?;
        let peer_signature = Signature::read_from_bytes(&peer_signature_bytes)
            .context("failed to decode handshake signature")?;
        ensure!(
            peer_validator_public_key.verify(commitment, &peer_signature),
            "peer handshake signature is invalid",
        );

        Ok(AuthenticatedPeer {
            validator_public_key: peer_validator_public_key,
            connection,
        })
    }
}

pub struct AuthenticatedPeer {
    validator_public_key: PublicKey,
    connection: Connection,
}

impl AuthenticatedPeer {
    fn endpoint_id(&self) -> EndpointId {
        self.connection.remote_id()
    }

    pub fn close(self) {
        self.connection.close(0u8.into(), b"connection check complete");
    }
}
