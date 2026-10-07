use anyhow::{Context, ensure};
use futures::future::try_join_all;
use golden_ehtdh1::Ehtdh1Material;
use golden_ehtdh1::wire::to_wire_bytes;
use miden_protocol::crypto::hash::rpo::Rpo256;

use super::super::wire::WireCodec;
use super::dkg::StorageGroup;
use super::dkg::confirmation::DkgDealingsCommitment;
use super::session::SessionId;
use super::{Ceremony, DkgParticipants};

/// Announces persistence of a bundle for one session, dealing transcript, and public output.
///
/// The public output excludes the private share because each validator holds a different share.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    session_id: SessionId,
    dealings_commitment: DkgDealingsCommitment,
    output_commitment: [u8; 32],
}

impl Completion {
    pub const BYTES: usize = SessionId::BYTES + DkgDealingsCommitment::BYTES + 32;
    const OUTPUT_DOMAIN: &'static [u8] = b"miden-validator-dkg-p2p-public-output-v1";

    pub fn new(
        participants: &DkgParticipants,
        dealings_commitment: DkgDealingsCommitment,
        output: &Ehtdh1Material<StorageGroup>,
    ) -> Self {
        let mut transcript = Self::OUTPUT_DOMAIN.to_vec();
        for bytes in [to_wire_bytes(&output.setup_context), to_wire_bytes(&output.public_key_set)] {
            transcript.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            transcript.extend_from_slice(&bytes);
        }
        Self {
            session_id: participants.session.id,
            dealings_commitment,
            output_commitment: Rpo256::hash(&transcript).as_bytes(),
        }
    }
}

impl WireCodec for Completion {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.session_id.encode();
        bytes.extend_from_slice(&self.dealings_commitment.encode());
        bytes.extend_from_slice(&self.output_commitment);
        bytes
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == Self::BYTES, "completion message must contain 96 bytes");
        let (session, rest) = bytes.split_at(SessionId::BYTES);
        let (dealings, output) = rest.split_at(DkgDealingsCommitment::BYTES);
        Ok(Self {
            session_id: SessionId::decode(session)?,
            dealings_commitment: DkgDealingsCommitment::decode(dealings)?,
            output_commitment: output
                .try_into()
                .context("output commitment must contain 32 bytes")?,
        })
    }
}

impl Ceremony {
    /// Announces local bundle persistence and waits for matching completion messages from every peer.
    ///
    /// Call this only after persistence succeeds. A missing or different peer completion must
    /// prevent the command from reporting ceremony success.
    pub async fn confirm_completion(
        &self,
        participants: &mut DkgParticipants,
        completion: Completion,
    ) -> anyhow::Result<()> {
        try_join_all(participants.session.authenticated_peers.iter_mut().map(|peer| async move {
            let peer_completion = peer.exchange_completion(&completion).await?;
            ensure!(
                peer_completion == completion,
                "validator {:?} reported a different ceremony completion: local {completion:?}, peer {peer_completion:?}",
                peer.validator_public_key(),
            );
            Ok::<_, anyhow::Error>(())
        }))
        .await?;
        Ok(())
    }
}
