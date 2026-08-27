use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, ensure};
use iroh::endpoint::{Connection, RecvStream, SendStream};
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

    fn signature_commitment(
        &self,
        sender_endpoint: EndpointId,
        receiver_endpoint: EndpointId,
    ) -> Word {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(HANDSHAKE_SIGNATURE_DOMAIN);
        transcript.extend_from_slice(sender_endpoint.as_bytes());
        transcript.extend_from_slice(receiver_endpoint.as_bytes());
        transcript.extend_from_slice(&self.to_bytes());
        Rpo256::hash(&transcript)
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
        let mut outgoing_peers = JoinSet::new();
        for peer_endpoint in peer_endpoints.iter().copied() {
            let endpoint = endpoint.clone();
            let handshake = self.clone();
            outgoing_peers.spawn(async move {
                handshake.connect_to_peer(endpoint, local_endpoint, peer_endpoint).await
            });
        }

        let mut expected_incoming = peer_endpoints.clone();
        let mut incoming_peers = JoinSet::new();
        while !expected_incoming.is_empty() {
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
            if !peer_endpoints.contains(&peer_endpoint) {
                connection.close(0u8.into(), b"endpoint is not a configured DKG peer");
                continue;
            }
            ensure!(
                expected_incoming.remove(&peer_endpoint),
                "duplicate connection from peer endpoint {peer_endpoint}",
            );
            let handshake = self.clone();
            incoming_peers.spawn(async move {
                handshake.authenticate_incoming(connection, local_endpoint).await
            });
        }

        let mut outgoing_by_endpoint = BTreeMap::new();
        while let Some(result) = outgoing_peers.join_next().await {
            let (peer_endpoint, connection, send) =
                result.context("outgoing peer task failed")??;
            outgoing_by_endpoint.insert(peer_endpoint, (connection, send));
        }

        let mut incoming_by_endpoint = BTreeMap::new();
        while let Some(result) = incoming_peers.join_next().await {
            let (peer_endpoint, validator_public_key, connection, receive) =
                result.context("incoming peer authentication task failed")??;
            incoming_by_endpoint.insert(peer_endpoint, (validator_public_key, connection, receive));
        }

        let mut authenticated = incoming_by_endpoint
            .into_iter()
            .map(|(peer_endpoint, (validator_public_key, incoming_connection, receive))| {
                let (outgoing_connection, send) = outgoing_by_endpoint
                    .remove(&peer_endpoint)
                    .context("missing outgoing connection to authenticated peer")?;
                Ok(AuthenticatedPeer {
                    validator_public_key,
                    outgoing_connection,
                    incoming_connection,
                    send,
                    receive,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
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

    async fn connect_to_peer(
        self,
        endpoint: Endpoint,
        local_endpoint: EndpointId,
        peer_endpoint: EndpointId,
    ) -> anyhow::Result<(EndpointId, Connection, SendStream)> {
        let connection = endpoint
            .connect(peer_endpoint, Self::ALPN)
            .await
            .with_context(|| format!("failed to connect to peer endpoint {peer_endpoint}"))?;
        let mut send = connection
            .open_uni()
            .await
            .context("failed to open outgoing handshake stream")?;
        let signature = self
            .signer
            .sign_commitment(self.message.signature_commitment(local_endpoint, peer_endpoint))
            .await?;
        send.write_all(&self.message.to_bytes())
            .await
            .context("failed to send handshake message")?;
        send.write_all(&signature.to_bytes())
            .await
            .context("failed to send handshake signature")?;
        Ok((peer_endpoint, connection, send))
    }

    async fn authenticate_incoming(
        self,
        connection: Connection,
        local_endpoint: EndpointId,
    ) -> anyhow::Result<(EndpointId, PublicKey, Connection, RecvStream)> {
        let peer_endpoint = connection.remote_id();
        let mut receive = connection
            .accept_uni()
            .await
            .context("failed to accept incoming handshake stream")?;
        let mut peer_message_bytes = [0; HANDSHAKE_MESSAGE_BYTES];
        receive
            .read_exact(&mut peer_message_bytes)
            .await
            .context("failed to read handshake message")?;
        let peer_message = HandshakeMessage::read_from_bytes(&peer_message_bytes)
            .context("failed to decode handshake message")?;
        self.message.validate_peer_configuration(&peer_message)?;

        let mut peer_signature_bytes = [0; VALIDATOR_SIGNATURE_BYTES];
        receive
            .read_exact(&mut peer_signature_bytes)
            .await
            .context("failed to read handshake signature")?;
        let peer_signature = Signature::read_from_bytes(&peer_signature_bytes)
            .context("failed to decode handshake signature")?;
        ensure!(
            peer_message.validator_public_key.verify(
                peer_message.signature_commitment(peer_endpoint, local_endpoint),
                &peer_signature,
            ),
            "peer handshake signature is invalid",
        );

        Ok((peer_endpoint, peer_message.validator_public_key, connection, receive))
    }
}

pub struct AuthenticatedPeer {
    validator_public_key: PublicKey,
    outgoing_connection: Connection,
    incoming_connection: Connection,
    send: SendStream,
    receive: RecvStream,
}

impl AuthenticatedPeer {
    fn endpoint_id(&self) -> EndpointId {
        self.outgoing_connection.remote_id()
    }

    pub fn close(self) {
        let Self {
            outgoing_connection,
            incoming_connection,
            send,
            receive,
            ..
        } = self;
        drop((send, receive));
        outgoing_connection.close(0u8.into(), b"connection check complete");
        incoming_connection.close(0u8.into(), b"connection check complete");
    }
}
