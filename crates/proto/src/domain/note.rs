use std::num::TryFromIntError;
use std::sync::Arc;

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
};
use miden_protocol::utils::{Deserializable, Serializable};
use miden_protocol::{MastForest, MastNodeId, Word};
use miden_standards::note::{AccountTargetNetworkNote, NetworkAccountTargetError};
use thiserror::Error;

use crate::domain::account::AccountConversionError;
use crate::domain::digest::DigestConversionError;
use crate::domain::merkle::MerkleConversionError;
use crate::errors::{MissingFieldHelper, ProtoConversionError};
use crate::generated as proto;

// NOTE CONVERSION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NoteConversionError {
    #[error(transparent)]
    Proto(#[from] ProtoConversionError),
    #[error(transparent)]
    Digest(#[from] DigestConversionError),
    #[error(transparent)]
    Merkle(#[from] MerkleConversionError),
    #[error(transparent)]
    Account(#[from] AccountConversionError),
    #[error("note error")]
    NoteError(#[from] miden_protocol::errors::NoteError),
    #[error("network note error")]
    NetworkNoteError(#[source] NetworkAccountTargetError),
    #[error("enum variant discriminant out of range")]
    EnumDiscriminantOutOfRange,
    #[error("integer conversion error: {0}")]
    TryFromIntError(#[from] TryFromIntError),
}

impl From<NoteConversionError> for tonic::Status {
    fn from(value: NoteConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}

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
    type Error = NoteConversionError;

    fn try_from(note_type: proto::note::NoteType) -> Result<Self, Self::Error> {
        match note_type {
            proto::note::NoteType::Public => Ok(NoteType::Public),
            proto::note::NoteType::Private => Ok(NoteType::Private),
            proto::note::NoteType::Unspecified => {
                Err(NoteConversionError::EnumDiscriminantOutOfRange)
            },
        }
    }
}

// NOTE METADATA
// ================================================================================================

impl TryFrom<proto::note::NoteMetadata> for NoteMetadata {
    type Error = NoteConversionError;

    fn try_from(value: proto::note::NoteMetadata) -> Result<Self, Self::Error> {
        let sender = value
            .sender
            .ok_or_else(|| proto::note::NoteMetadata::missing_field(stringify!(sender)))?
            .try_into()
            .map_err(NoteConversionError::from)?;
        let note_type = proto::note::NoteType::try_from(value.note_type)
            .map_err(|_| NoteConversionError::EnumDiscriminantOutOfRange)?
            .try_into()?;
        let tag = NoteTag::new(value.tag);

        // Deserialize attachment if present
        let attachment = if value.attachment.is_empty() {
            NoteAttachment::default()
        } else {
            NoteAttachment::read_from_bytes(&value.attachment)
                .map_err(|err| ProtoConversionError::deserialization_error("NoteAttachment", err))?
        };

        Ok(NoteMetadata::new(sender, note_type).with_tag(tag).with_attachment(attachment))
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

impl From<AccountTargetNetworkNote> for proto::note::NetworkNote {
    fn from(note: AccountTargetNetworkNote) -> Self {
        let note = note.into_note();
        Self {
            metadata: Some(proto::note::NoteMetadata::from(note.metadata().clone())),
            details: NoteDetails::from(note).to_bytes(),
        }
    }
}

impl TryFrom<proto::note::NetworkNote> for AccountTargetNetworkNote {
    type Error = NoteConversionError;

    fn try_from(value: proto::note::NetworkNote) -> Result<Self, Self::Error> {
        let details = NoteDetails::read_from_bytes(&value.details)
            .map_err(|err| ProtoConversionError::deserialization_error("NoteDetails", err))?;
        let (assets, recipient) = details.into_parts();
        let metadata: NoteMetadata = value
            .metadata
            .ok_or_else(|| proto::note::NetworkNote::missing_field(stringify!(metadata)))?
            .try_into()?;
        let note = Note::new(assets, metadata, recipient);
        AccountTargetNetworkNote::new(note).map_err(NoteConversionError::NetworkNoteError)
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
    type Error = DigestConversionError;

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
    type Error = NoteConversionError;

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
    type Error = NoteConversionError;

    fn try_from(proto_note: proto::note::Note) -> Result<Self, Self::Error> {
        let metadata: NoteMetadata = proto_note
            .metadata
            .ok_or(proto::note::Note::missing_field(stringify!(metadata)))?
            .try_into()?;

        let details = proto_note
            .details
            .ok_or(proto::note::Note::missing_field(stringify!(details)))?;

        let note_details = NoteDetails::read_from_bytes(&details)
            .map_err(|err| ProtoConversionError::deserialization_error("NoteDetails", err))?;

        let (assets, recipient) = note_details.into_parts();
        Ok(Note::new(assets, metadata, recipient))
    }
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
    type Error = NoteConversionError;

    fn try_from(value: proto::note::NoteScript) -> Result<Self, Self::Error> {
        let proto::note::NoteScript { entrypoint, mast } = value;

        let mast = MastForest::read_from_bytes(&mast)
            .map_err(|err| ProtoConversionError::deserialization_error("note_script.mast", err))?;
        let entrypoint = MastNodeId::from_u32_safe(entrypoint, &mast).map_err(|err| {
            ProtoConversionError::deserialization_error("note_script.entrypoint", err)
        })?;

        Ok(Self::from_parts(Arc::new(mast), entrypoint))
    }
}
