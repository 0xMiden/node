use std::sync::Arc;

use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    Note,
    NoteAttachment,
    NoteAttachmentKind,
    NoteDetails,
    NoteHeader,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteMetadataHeader,
    NoteScript,
    NoteTag,
    NoteType,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{MastForest, MastNodeId, Word};
use miden_standards::note::AccountTargetNetworkNote;

use crate::errors::{ConversionError, ConversionResultExt, DecodeBytesExt, GrpcDecodeExt};
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

// NOTE ATTACHMENT KIND
// ================================================================================================

impl From<NoteAttachmentKind> for proto::note::NoteAttachmentKind {
    fn from(kind: NoteAttachmentKind) -> Self {
        match kind {
            NoteAttachmentKind::None => proto::note::NoteAttachmentKind::None,
            NoteAttachmentKind::Word => proto::note::NoteAttachmentKind::Word,
            NoteAttachmentKind::Array => proto::note::NoteAttachmentKind::Array,
        }
    }
}

impl TryFrom<proto::note::NoteAttachmentKind> for NoteAttachmentKind {
    type Error = ConversionError;

    fn try_from(kind: proto::note::NoteAttachmentKind) -> Result<Self, Self::Error> {
        match kind {
            proto::note::NoteAttachmentKind::None => Ok(NoteAttachmentKind::None),
            proto::note::NoteAttachmentKind::Word => Ok(NoteAttachmentKind::Word),
            proto::note::NoteAttachmentKind::Array => Ok(NoteAttachmentKind::Array),
            proto::note::NoteAttachmentKind::Unspecified => {
                Err(ConversionError::EnumDiscriminantOutOfRange)
            },
        }
    }
}

// NOTE METADATA HEADER
// ================================================================================================

impl From<NoteMetadataHeader> for proto::note::NoteMetadataHeader {
    fn from(header: NoteMetadataHeader) -> Self {
        Self {
            sender: Some(header.sender().into()),
            note_type: proto::note::NoteType::from(header.note_type()) as i32,
            tag: header.tag().as_u32(),
            attachment_kind: proto::note::NoteAttachmentKind::from(header.attachment_kind()) as i32,
            attachment_scheme: header.attachment_scheme().as_u32(),
        }
    }
}

// NOTE METADATA
// ================================================================================================

impl TryFrom<proto::note::NoteMetadata> for NoteMetadata {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteMetadata) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let sender = decoder.decode_field("sender", value.sender)?;
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

impl TryFrom<proto::note::NetworkNote> for AccountTargetNetworkNote {
    type Error = ConversionError;

    fn try_from(value: proto::note::NetworkNote) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let details = NoteDetails::decode_bytes(&value.details, "NoteDetails")?;
        let (assets, recipient) = details.into_parts();
        let metadata: NoteMetadata = decoder.decode_field("metadata", value.metadata)?;
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
            note_index_in_block: proof.location().block_note_tree_index().into(),
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

impl TryFrom<proto::note::Note> for Note {
    type Error = ConversionError;

    fn try_from(proto_note: proto::note::Note) -> Result<Self, Self::Error> {
        let decoder = proto_note.decoder();
        let metadata: NoteMetadata = decoder.decode_field("metadata", proto_note.metadata)?;

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

impl TryFrom<proto::note::NoteHeader> for NoteHeader {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteHeader) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let note_id_word: Word = decoder.decode_field("note_id", value.note_id)?;
        let metadata: NoteMetadata = decoder.decode_field("metadata", value.metadata)?;

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
