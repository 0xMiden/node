use std::fmt;

use anyhow::{Context, ensure};
use futures::future::try_join_all;
use miden_protocol::crypto::hash::rpo::Rpo256;

use super::{Ceremony, DkgDealings, DkgParticipants, UnconfirmedDkgDealings};
use crate::commands::dkg_p2p::wire::WireCodec;

/// Commits to the session, registry, then decryption and context roots in participant order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgDealingsCommitment([u8; 32]);

impl DkgDealingsCommitment {
    pub const BYTES: usize = 32;
    const DOMAIN: &'static [u8] = b"miden-validator-dkg-p2p-dealings-v1";

    fn from_dealings(participants: &DkgParticipants, dealings: &UnconfirmedDkgDealings) -> Self {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(Self::DOMAIN);
        transcript.extend_from_slice(&participants.session.id.encode());
        transcript.extend_from_slice(&participants.registry.root());
        for (local, peers) in [
            (&dealings.local.decryption_dealing.message, &dealings.peer_decryption_dealings),
            (&dealings.local.context_dealing.message, &dealings.peer_context_dealings),
        ] {
            let mut messages = std::iter::once(local).chain(peers.values()).collect::<Vec<_>>();
            messages.sort_by_key(|message| message.dealer);
            transcript.extend_from_slice(&(messages.len() as u64).to_be_bytes());
            for message in messages {
                transcript.extend_from_slice(&message.dealer.get().to_be_bytes());
                transcript.extend_from_slice(&message.transcript_root);
            }
        }
        Self(Rpo256::hash(&transcript).as_bytes())
    }
}

impl WireCodec for DkgDealingsCommitment {
    fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes = bytes.try_into().context("DKG dealings commitment must contain 32 bytes")?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for DkgDealingsCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Ceremony {
    pub async fn confirm_dealings(
        &self,
        participants: &mut DkgParticipants,
        dealings: UnconfirmedDkgDealings,
    ) -> anyhow::Result<DkgDealings> {
        let commitment = DkgDealingsCommitment::from_dealings(participants, &dealings);
        let confirmations = participants.session.authenticated_peers.iter_mut().map(|peer| async move {
            let peer_commitment = peer.exchange_dealings_commitment(&commitment).await?;
            ensure!(
                peer_commitment == commitment,
                "validator {:?} received different DKG dealings: local {commitment}, peer {peer_commitment}",
                peer.validator_public_key(),
            );
            Ok::<_, anyhow::Error>(())
        });
        try_join_all(confirmations).await?;

        let UnconfirmedDkgDealings {
            local,
            peer_decryption_dealings,
            peer_context_dealings,
        } = dealings;
        Ok(DkgDealings {
            local,
            peer_decryption_dealings,
            peer_context_dealings,
            commitment,
        })
    }
}
