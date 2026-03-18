use std::sync::Arc;

use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    Note,
    NoteAttachment,
    NoteDetails,
    NoteHeader,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteScript,
    NoteTag,
    NoteType,
};
use miden_protocol::utils::Serializable;
use miden_protocol::{MastForest, MastNodeId, Word};
use miden_standards::note::AccountTargetNetworkNote;

use crate::errors::{
    ConversionError,
    ConversionResultExt,
    DecodeBytesExt,
    GrpcDecodeExt as _,
    grpc_decode,
};
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
            proto::note::NoteType::Unspecified => {
                Err(ConversionError::message("enum variant discriminant out of range"))
            },
        }
    }
}

// NOTE METADATA
// ================================================================================================

#[grpc_decode]
impl TryFrom<proto::note::NoteMetadata> for NoteMetadata {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteMetadata) -> Result<Self, Self::Error> {
        let sender = value.sender.decode()?;
        let note_type = proto::note::NoteType::try_from(value.note_type)
            .map_err(|_| ConversionError::message("enum variant discriminant out of range"))?
            .try_into()
            .context("note_type")?;
        let tag = NoteTag::new(value.tag);

        // Deserialize attachment if present
        let attachment = if value.attachment.is_empty() {
            NoteAttachment::default()
        } else {
            NoteAttachment::decode_bytes(&value.attachment, "NoteAttachment")?
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

#[grpc_decode]
impl TryFrom<proto::note::NetworkNote> for AccountTargetNetworkNote {
    type Error = ConversionError;

    fn try_from(value: proto::note::NetworkNote) -> Result<Self, Self::Error> {
        let details = NoteDetails::decode_bytes(&value.details, "NoteDetails")?;
        let (assets, recipient) = details.into_parts();
        let metadata: NoteMetadata = value.metadata.decode()?;
        let note = Note::new(assets, metadata, recipient);
        AccountTargetNetworkNote::new(note).map_err(ConversionError::from)
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
            .ok_or(ConversionError::missing_field::<proto::note::NoteId>("id"))?
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
                .ok_or(ConversionError::missing_field::<proto::note::NoteInclusionInBlockProof>(
                    "inclusion_path",
                ))?
                .clone(),
        )
        .context("inclusion_path")?;

        let note_id = Word::try_from(
            proof
                .note_id
                .as_ref()
                .ok_or(ConversionError::missing_field::<proto::note::NoteInclusionInBlockProof>(
                    "note_id",
                ))?
                .id
                .as_ref()
                .ok_or(ConversionError::missing_field::<proto::note::NoteId>("id"))?,
        )
        .context("note_id")?;

        Ok((
            NoteId::from_raw(note_id),
            NoteInclusionProof::new(
                proof.block_num.into(),
                proof.note_index_in_block.try_into().context("note_index_in_block")?,
                inclusion_path,
            )?,
        ))
    }
}

#[grpc_decode]
impl TryFrom<proto::note::Note> for Note {
    type Error = ConversionError;

    fn try_from(proto_note: proto::note::Note) -> Result<Self, Self::Error> {
        let metadata: NoteMetadata = proto_note.metadata.decode()?;

        let details = proto_note
            .details
            .ok_or(ConversionError::missing_field::<proto::note::Note>("details"))?;

        let note_details = NoteDetails::decode_bytes(&details, "NoteDetails")?;

        let (assets, recipient) = note_details.into_parts();
        Ok(Note::new(assets, metadata, recipient))
    }
}

// NOTE HEADER
// ================================================================================================

impl From<NoteHeader> for proto::note::NoteHeader {
    fn from(header: NoteHeader) -> Self {
        Self {
            note_id: Some((&header.id()).into()),
            metadata: Some(header.into_metadata().into()),
        }
    }
}

#[grpc_decode]
impl TryFrom<proto::note::NoteHeader> for NoteHeader {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteHeader) -> Result<Self, Self::Error> {
        let note_id_word: Word = value.note_id.decode()?;
        let metadata: NoteMetadata = value.metadata.decode()?;

        Ok(NoteHeader::new(NoteId::from_raw(note_id_word), metadata))
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
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteScript) -> Result<Self, Self::Error> {
        let proto::note::NoteScript { entrypoint, mast } = value;

        let mast = MastForest::decode_bytes(&mast, "note_script.mast")?;
        let entrypoint = MastNodeId::from_u32_safe(entrypoint, &mast)
            .map_err(|err| ConversionError::deserialization("note_script.entrypoint", err))?;

        Ok(Self::from_parts(Arc::new(mast), entrypoint))
    }
}
