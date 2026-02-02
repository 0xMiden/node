use std::sync::Arc;

use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    Note,
    NoteAttachment,
    NoteDetails,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteScript,
    NoteTag,
    NoteType,
    Nullifier,
};
use miden_protocol::utils::{Deserializable, Serializable};
use miden_protocol::{MastForest, MastNodeId, Word};
use miden_standards::note::{NetworkAccountTarget, NetworkAccountTargetError};
use thiserror::Error;

use super::account::NetworkAccountId;
use crate::errors::{ConversionError, MissingFieldHelper};
use crate::generated as proto;

// NOTE TYPE
// ================================================================================================

impl From<NoteType> for proto::note::NoteType {
    fn from(note_type: NoteType) -> Self {
        match note_type {
            NoteType::Public => proto::note::NoteType::Public,
            NoteType::Private => proto::note::NoteType::Private,
        }
    }
}

impl TryFrom<proto::note::NoteType> for NoteType {
    type Error = ConversionError;

    fn try_from(note_type: proto::note::NoteType) -> Result<Self, Self::Error> {
        match note_type {
            proto::note::NoteType::Public => Ok(NoteType::Public),
            proto::note::NoteType::Private => Ok(NoteType::Private),
            proto::note::NoteType::Unspecified => Err(ConversionError::EnumDiscriminantOutOfRange),
        }
    }
}

// NOTE METADATA
// ================================================================================================

impl TryFrom<proto::note::NoteMetadata> for NoteMetadata {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteMetadata) -> Result<Self, Self::Error> {
        let sender = value
            .sender
            .ok_or_else(|| proto::note::NoteMetadata::missing_field(stringify!(sender)))?
            .try_into()?;
        let note_type = proto::note::NoteType::try_from(value.note_type)
            .map_err(|_| ConversionError::EnumDiscriminantOutOfRange)?
            .try_into()?;
        let tag = NoteTag::new(value.tag);

        // Deserialize attachment if present
        let attachment = if value.attachment.is_empty() {
            NoteAttachment::default()
        } else {
            NoteAttachment::read_from_bytes(&value.attachment)
                .map_err(|err| ConversionError::deserialization_error("NoteAttachment", err))?
        };

        Ok(NoteMetadata::new(sender, note_type, tag).with_attachment(attachment))
    }
}

impl From<Note> for proto::note::NetworkNote {
    fn from(note: Note) -> Self {
        Self {
            metadata: Some(proto::note::NoteMetadata::from(note.metadata().clone())),
            details: NoteDetails::from(note).to_bytes(),
        }
    }
}

impl From<Note> for proto::note::Note {
    fn from(note: Note) -> Self {
        Self {
            metadata: Some(proto::note::NoteMetadata::from(note.metadata().clone())),
            details: Some(NoteDetails::from(note).to_bytes()),
        }
    }
}

impl From<NetworkNote> for proto::note::NetworkNote {
    fn from(note: NetworkNote) -> Self {
        let note = Note::from(note);
        Self {
            metadata: Some(proto::note::NoteMetadata::from(note.metadata().clone())),
            details: NoteDetails::from(note).to_bytes(),
        }
    }
}

impl From<NoteMetadata> for proto::note::NoteMetadata {
    fn from(val: NoteMetadata) -> Self {
        let sender = Some(val.sender().into());
        let note_type = proto::note::NoteType::from(val.note_type()) as i32;
        let tag = val.tag().as_u32();
        let attachment = val.attachment().to_bytes();

        proto::note::NoteMetadata { sender, note_type, tag, attachment }
    }
}

impl From<Word> for proto::note::NoteId {
    fn from(digest: Word) -> Self {
        Self { id: Some(digest.into()) }
    }
}

impl TryFrom<proto::note::NoteId> for Word {
    type Error = ConversionError;

    fn try_from(note_id: proto::note::NoteId) -> Result<Self, Self::Error> {
        note_id
            .id
            .as_ref()
            .ok_or(proto::note::NoteId::missing_field(stringify!(id)))?
            .try_into()
    }
}

impl From<&NoteId> for proto::note::NoteId {
    fn from(note_id: &NoteId) -> Self {
        Self { id: Some(note_id.into()) }
    }
}

impl From<(&NoteId, &NoteInclusionProof)> for proto::note::NoteInclusionInBlockProof {
    fn from((note_id, proof): (&NoteId, &NoteInclusionProof)) -> Self {
        Self {
            note_id: Some(note_id.into()),
            block_num: proof.location().block_num().as_u32(),
            note_index_in_block: proof.location().node_index_in_block().into(),
            inclusion_path: Some(proof.note_path().clone().into()),
        }
    }
}

impl TryFrom<&proto::note::NoteInclusionInBlockProof> for (NoteId, NoteInclusionProof) {
    type Error = ConversionError;

    fn try_from(
        proof: &proto::note::NoteInclusionInBlockProof,
    ) -> Result<(NoteId, NoteInclusionProof), Self::Error> {
        let inclusion_path = SparseMerklePath::try_from(
            proof
                .inclusion_path
                .as_ref()
                .ok_or(proto::note::NoteInclusionInBlockProof::missing_field(stringify!(
                    inclusion_path
                )))?
                .clone(),
        )?;

        let note_id = Word::try_from(
            proof
                .note_id
                .as_ref()
                .ok_or(proto::note::NoteInclusionInBlockProof::missing_field(stringify!(note_id)))?
                .id
                .as_ref()
                .ok_or(proto::note::NoteId::missing_field(stringify!(id)))?,
        )?;

        Ok((
            NoteId::from_raw(note_id),
            NoteInclusionProof::new(
                proof.block_num.into(),
                proof.note_index_in_block.try_into()?,
                inclusion_path,
            )?,
        ))
    }
}

impl TryFrom<proto::note::Note> for Note {
    type Error = ConversionError;

    fn try_from(proto_note: proto::note::Note) -> Result<Self, Self::Error> {
        let metadata: NoteMetadata = proto_note
            .metadata
            .ok_or(proto::note::Note::missing_field(stringify!(metadata)))?
            .try_into()?;

        let details = proto_note
            .details
            .ok_or(proto::note::Note::missing_field(stringify!(details)))?;

        let note_details = NoteDetails::read_from_bytes(&details)
            .map_err(|err| ConversionError::deserialization_error("NoteDetails", err))?;

        let (assets, recipient) = note_details.into_parts();
        Ok(Note::new(assets, metadata, recipient))
    }
}

// NETWORK NOTE
// ================================================================================================

/// An enum that wraps around notes used in a network mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkNote {
    SingleTarget(SingleTargetNetworkNote),
}

impl NetworkNote {
    pub fn inner(&self) -> &Note {
        match self {
            NetworkNote::SingleTarget(note) => note.inner(),
        }
    }

    pub fn metadata(&self) -> &NoteMetadata {
        self.inner().metadata()
    }

    pub fn nullifier(&self) -> Nullifier {
        self.inner().nullifier()
    }

    pub fn id(&self) -> NoteId {
        self.inner().id()
    }
}

impl From<NetworkNote> for Note {
    fn from(value: NetworkNote) -> Self {
        match value {
            NetworkNote::SingleTarget(note) => note.into(),
        }
    }
}

impl TryFrom<Note> for NetworkNote {
    type Error = NetworkNoteError;

    fn try_from(note: Note) -> Result<Self, Self::Error> {
        SingleTargetNetworkNote::try_from(note).map(NetworkNote::SingleTarget)
    }
}

impl TryFrom<proto::note::NetworkNote> for NetworkNote {
    type Error = ConversionError;

    fn try_from(proto_note: proto::note::NetworkNote) -> Result<Self, Self::Error> {
        from_proto(proto_note)
    }
}

// SINGLE TARGET NETWORK NOTE
// ================================================================================================

/// A newtype that wraps around notes targeting a single network account.
///
/// A note is considered a single-target network note if its attachment
/// is a valid `NetworkAccountTarget`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleTargetNetworkNote {
    note: Note,
    account_target: NetworkAccountTarget,
}

impl SingleTargetNetworkNote {
    pub fn inner(&self) -> &Note {
        &self.note
    }

    pub fn metadata(&self) -> &NoteMetadata {
        self.inner().metadata()
    }

    pub fn nullifier(&self) -> Nullifier {
        self.inner().nullifier()
    }

    pub fn id(&self) -> NoteId {
        self.inner().id()
    }

    /// The network account ID that this note targets.
    pub fn account_id(&self) -> NetworkAccountId {
        self.account_target.target_id().try_into().expect("always a network account ID")
    }

    pub fn can_be_consumed(&self, block_num: BlockNumber) -> Option<bool> {
        self.account_target.execution_hint().can_be_consumed(block_num)
    }
}

impl From<SingleTargetNetworkNote> for Note {
    fn from(value: SingleTargetNetworkNote) -> Self {
        value.note
    }
}

impl TryFrom<Note> for SingleTargetNetworkNote {
    type Error = NetworkNoteError;

    fn try_from(note: Note) -> Result<Self, Self::Error> {
        // Single-target network notes are identified by having a NetworkAccountTarget attachment
        let attachment = note.metadata().attachment();
        let account_target = NetworkAccountTarget::try_from(attachment)
            .map_err(NetworkNoteError::InvalidAttachment)?;
        Ok(Self { note, account_target })
    }
}

impl TryFrom<proto::note::NetworkNote> for SingleTargetNetworkNote {
    type Error = ConversionError;

    fn try_from(proto_note: proto::note::NetworkNote) -> Result<Self, Self::Error> {
        from_proto(proto_note)
    }
}

/// Helper function to deduplicate implementations `TryFrom<proto::note::NetworkNote>`.
fn from_proto<T>(proto_note: proto::note::NetworkNote) -> Result<T, ConversionError>
where
    T: TryFrom<Note>,
    T::Error: Into<ConversionError>,
{
    let details = NoteDetails::read_from_bytes(&proto_note.details)
        .map_err(|err| ConversionError::deserialization_error("NoteDetails", err))?;
    let (assets, recipient) = details.into_parts();
    let metadata: NoteMetadata = proto_note
        .metadata
        .ok_or_else(|| proto::note::NetworkNote::missing_field(stringify!(metadata)))?
        .try_into()?;
    let note = Note::new(assets, metadata, recipient);
    T::try_from(note).map_err(Into::into)
}

#[derive(Debug, Error)]
pub enum NetworkNoteError {
    #[error("note does not have a valid NetworkAccountTarget attachment: {0}")]
    InvalidAttachment(#[source] NetworkAccountTargetError),
}

// NOTE SCRIPT
// ================================================================================================

impl From<NoteScript> for proto::note::NoteScript {
    fn from(script: NoteScript) -> Self {
        Self {
            entrypoint: script.entrypoint().into(),
            mast: script.mast().to_bytes(),
        }
    }
}

impl TryFrom<proto::note::NoteScript> for NoteScript {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteScript) -> Result<Self, Self::Error> {
        let proto::note::NoteScript { entrypoint, mast } = value;

        let mast = MastForest::read_from_bytes(&mast)
            .map_err(|err| Self::Error::deserialization_error("note_script.mast", err))?;
        let entrypoint = MastNodeId::from_u32_safe(entrypoint, &mast)
            .map_err(|err| Self::Error::deserialization_error("note_script.entrypoint", err))?;

        Ok(Self::from_parts(Arc::new(mast), entrypoint))
    }
}
