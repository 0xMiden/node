use anyhow::{Context, ensure};

use super::{CommonArtifact, ParticipantArtifact};

pub(super) const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const COMMON_ARTIFACT_COUNT: usize = 3;
const ARTIFACTS_PER_PARTICIPANT: usize = 4;
const MAX_VALUES_PER_SLOT: usize = 2;

/// One immutable location in a DKG ceremony board.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands::dkg) enum ArtifactSlot {
    Registration(u32),
    Manifest,
    DecryptionConfig,
    ContextConfig,
    DecryptionDealing(u32),
    ContextDealing(u32),
    TranscriptAcceptance(u32),
}

impl ArtifactSlot {
    pub(super) fn prefix(&self) -> String {
        match self {
            Self::Registration(participant) => format!("registration/{participant}/"),
            Self::Manifest => "common/manifest/".to_owned(),
            Self::DecryptionConfig => "common/decryption-config/".to_owned(),
            Self::ContextConfig => "common/context-config/".to_owned(),
            Self::DecryptionDealing(participant) => {
                format!("dealing/{participant}/decryption/")
            },
            Self::ContextDealing(participant) => format!("dealing/{participant}/context/"),
            Self::TranscriptAcceptance(participant) => {
                format!("acceptance/{participant}/signature/")
            },
        }
    }
}

impl CommonArtifact {
    pub(super) fn slot(self) -> ArtifactSlot {
        match self {
            Self::Manifest => ArtifactSlot::Manifest,
            Self::DecryptionConfig => ArtifactSlot::DecryptionConfig,
            Self::ContextConfig => ArtifactSlot::ContextConfig,
        }
    }
}

impl ParticipantArtifact {
    pub(super) fn slot(self, participant: u32) -> ArtifactSlot {
        match self {
            Self::Registration => ArtifactSlot::Registration(participant),
            Self::DecryptionDealing => ArtifactSlot::DecryptionDealing(participant),
            Self::ContextDealing => ArtifactSlot::ContextDealing(participant),
            Self::TranscriptAcceptance => ArtifactSlot::TranscriptAcceptance(participant),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct BoardCore {
    allowed_prefixes: Vec<String>,
    max_document_entries: usize,
}

impl BoardCore {
    pub(super) fn new(participant_count: usize) -> anyhow::Result<Self> {
        ensure!(participant_count > 0, "DKG board requires at least one participant");
        let artifact_slot_count = participant_count
            .checked_mul(ARTIFACTS_PER_PARTICIPANT)
            .and_then(|count| count.checked_add(COMMON_ARTIFACT_COUNT))
            .context("DKG board participant count is too large")?;
        let max_document_entries = artifact_slot_count
            .checked_mul(MAX_VALUES_PER_SLOT)
            .context("DKG board participant count is too large")?;
        let mut allowed_prefixes = vec![
            ArtifactSlot::Manifest.prefix(),
            ArtifactSlot::DecryptionConfig.prefix(),
            ArtifactSlot::ContextConfig.prefix(),
        ];
        for position in 0..participant_count {
            let participant = u32::try_from(position + 1).context("too many DKG participants")?;
            allowed_prefixes.extend([
                ArtifactSlot::Registration(participant).prefix(),
                ArtifactSlot::DecryptionDealing(participant).prefix(),
                ArtifactSlot::ContextDealing(participant).prefix(),
                ArtifactSlot::TranscriptAcceptance(participant).prefix(),
            ]);
        }
        Ok(Self { allowed_prefixes, max_document_entries })
    }

    pub(super) fn allowed_prefixes(&self) -> &[String] {
        &self.allowed_prefixes
    }

    pub(super) fn max_document_entries(&self) -> usize {
        self.max_document_entries
    }

    pub(super) fn validate_slot(&self, slot: &ArtifactSlot) -> anyhow::Result<()> {
        ensure!(
            self.allowed_prefixes.contains(&slot.prefix()),
            "DKG board upload targets an unknown participant or artifact slot"
        );
        Ok(())
    }
}

pub(super) fn validate_artifact_length(length: usize) -> anyhow::Result<()> {
    ensure!(length > 0, "DKG board artifact must not be empty");
    ensure!(
        u64::try_from(length).context("artifact length does not fit u64")? <= MAX_ARTIFACT_BYTES,
        "DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes",
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublishAction {
    AlreadyPresent,
    Insert,
}

pub(super) struct SlotValues<T> {
    values: Vec<T>,
}

impl<T: Eq> SlotValues<T> {
    pub(super) fn from_values(values: impl IntoIterator<Item = T>) -> Self {
        let mut unique = Vec::new();
        for value in values {
            if !unique.contains(&value) {
                unique.push(value);
            }
        }
        Self { values: unique }
    }

    pub(super) fn publish(&self, value: &T) -> anyhow::Result<PublishAction> {
        if self.values.contains(value) {
            return Ok(PublishAction::AlreadyPresent);
        }
        ensure!(
            self.values.len() < MAX_VALUES_PER_SLOT,
            "DKG board artifact slot already contains conflicting values"
        );
        Ok(PublishAction::Insert)
    }

    pub(super) fn into_unique(self, slot: &ArtifactSlot) -> anyhow::Result<Option<T>> {
        ensure!(
            self.values.len() <= 1,
            "DKG board contains conflicting artifacts for {}",
            slot.prefix()
        );
        Ok(self.values.into_iter().next())
    }
}
