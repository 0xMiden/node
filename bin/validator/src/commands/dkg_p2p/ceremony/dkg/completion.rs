use anyhow::Context;
use golden_core::complete;
use golden_ehtdh1::{Ehtdh1Material, material_from_dkg_outputs};
use golden_evrf::paper::secp_secq::SecpSecqBackend;

use super::{Ceremony, DkgDealings, DkgParticipants, StorageGroup};

impl Ceremony {
    /// Derives this validator's key material from the confirmed decryption and context dealings.
    pub fn complete_dkg(
        &self,
        participants: &DkgParticipants,
        dealings: DkgDealings,
    ) -> anyhow::Result<Ehtdh1Material<StorageGroup>> {
        let DkgDealings {
            local,
            peer_decryption_dealings,
            peer_context_dealings,
            ..
        } = dealings;
        let decryption_output = complete::<StorageGroup, SecpSecqBackend>(
            participants.local_index,
            &participants.secret_key.0,
            &local.decryption_dealing,
            &peer_decryption_dealings,
            &local.decryption_config,
        )
        .context("failed to complete decryption DKG")?;
        let context_output = complete::<StorageGroup, SecpSecqBackend>(
            participants.local_index,
            &participants.secret_key.0,
            &local.context_dealing,
            &peer_context_dealings,
            &local.context_config,
        )
        .context("failed to complete context DKG")?;

        material_from_dkg_outputs(
            &local.decryption_config,
            &decryption_output,
            &local.context_config,
            &context_output,
            *self.epoch.as_bytes(),
        )
        .context("failed to derive storage key material from DKG outputs")
    }
}
