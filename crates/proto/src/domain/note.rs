use std::sync::Arc;

use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    Note,
    NoteAttachmentHeader,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteDetails,
    NoteHeader,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteScript,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{MastForest, MastNodeId, Word};
use miden_standards::note::AccountTargetNetworkNote;

use crate::decode::{ConversionResultExt, DecodeBytesExt, GrpcDecodeExt};
use crate::errors::ConversionError;
use crate::{decode, generated as proto};

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

impl From<NoteMetadata> for proto::note::NoteMetadata {
    fn from(val: NoteMetadata) -> Self {
        let sender = Some(val.sender().into());
        let note_type = proto::note::NoteType::from(val.note_type()) as i32;
        let tag = val.tag().as_u32();
        let attachment_schemes = val
            .attachment_headers()
            .iter()
            .map(|header| u32::from(header.scheme().map_or(0, |s| s.as_u16())))
            .collect();
        let attachments_commitment = Some(val.attachments_commitment().into());

        proto::note::NoteMetadata {
            sender,
            note_type,
            tag,
            attachment_schemes,
            attachments_commitment,
        }
    }
}

impl TryFrom<proto::note::NoteMetadata> for NoteMetadata {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteMetadata) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let sender = decode!(decoder, value.sender)?;
        let note_type = proto::note::NoteType::try_from(value.note_type)
            .map_err(|_| ConversionError::message("enum variant discriminant out of range"))?
            .try_into()
            .context("note_type")?;
        let tag = NoteTag::new(value.tag);
        let attachments_commitment: Word = decode!(decoder, value.attachments_commitment)?;

        if value.attachment_schemes.len() > NoteAttachments::MAX_COUNT {
            return Err(ConversionError::message("too many attachment schemes"));
        }
        let mut attachment_headers = [NoteAttachmentHeader::absent(); NoteAttachments::MAX_COUNT];
        for (slot, raw) in attachment_headers.iter_mut().zip(value.attachment_schemes) {
            let raw = u16::try_from(raw)
                .map_err(|_| ConversionError::message("attachment scheme out of u16 range"))?;
            *slot = if raw == 0 {
                NoteAttachmentHeader::absent()
            } else {
                NoteAttachmentHeader::new(NoteAttachmentScheme::new(raw)?)
            };
        }

        let partial = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        Ok(NoteMetadata::from_parts(partial, attachment_headers, attachments_commitment))
    }
}

// NOTE
// ================================================================================================

impl From<Note> for proto::note::NetworkNote {
    fn from(note: Note) -> Self {
        let metadata = Some(proto::note::NoteMetadata::from(*note.metadata()));
        let attachments = note.attachments().to_bytes();
        let details = NoteDetails::from(note).to_bytes();
        Self { metadata, details, attachments }
    }
}

impl From<Note> for proto::note::Note {
    fn from(note: Note) -> Self {
        let metadata = Some(proto::note::NoteMetadata::from(*note.metadata()));
        let attachments = note.attachments().to_bytes();
        let details = Some(NoteDetails::from(note).to_bytes());
        Self { metadata, details, attachments }
    }
}

impl From<AccountTargetNetworkNote> for proto::note::NetworkNote {
    fn from(note: AccountTargetNetworkNote) -> Self {
        note.into_note().into()
    }
}

impl TryFrom<proto::note::NetworkNote> for AccountTargetNetworkNote {
    type Error = ConversionError;

    fn try_from(value: proto::note::NetworkNote) -> Result<Self, Self::Error> {
        let proto::note::NetworkNote { metadata, details, attachments } = value;

        let metadata = metadata
            .ok_or(ConversionError::missing_field::<proto::note::NetworkNote>("metadata"))?;
        let partial_metadata = partial_note_metadata_from_proto(metadata)?;

        let note_details = NoteDetails::decode_bytes(&details, "NoteDetails")?;
        let (assets, recipient) = note_details.into_parts();
        let attachments = decode_attachments(&attachments)?;

        let note = Note::with_attachments(assets, partial_metadata, recipient, attachments);
        AccountTargetNetworkNote::new(note).map_err(ConversionError::from)
    }
}

impl TryFrom<proto::note::Note> for Note {
    type Error = ConversionError;

    fn try_from(proto_note: proto::note::Note) -> Result<Self, Self::Error> {
        let proto::note::Note { metadata, details, attachments } = proto_note;

        let metadata =
            metadata.ok_or(ConversionError::missing_field::<proto::note::Note>("metadata"))?;
        let partial_metadata = partial_note_metadata_from_proto(metadata)?;

        let details =
            details.ok_or(ConversionError::missing_field::<proto::note::Note>("details"))?;
        let note_details = NoteDetails::decode_bytes(&details, "NoteDetails")?;
        let (assets, recipient) = note_details.into_parts();
        let attachments = decode_attachments(&attachments)?;

        Ok(Note::with_attachments(assets, partial_metadata, recipient, attachments))
    }
}

// NOTE ID
// ================================================================================================

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
        let note_id_word: Word = decode!(decoder, value.note_id)?;
        let metadata: NoteMetadata = decode!(decoder, value.metadata)?;

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

// HELPERS
// ================================================================================================

/// Decodes the `(sender, note_type, tag)` triple from a proto `NoteMetadata` into a
/// [`PartialNoteMetadata`]. The attachment-related fields on the proto are ignored — when full
/// attachments are also transmitted, the receiver derives the canonical headers and commitment from
/// those instead.
fn partial_note_metadata_from_proto(
    value: proto::note::NoteMetadata,
) -> Result<PartialNoteMetadata, ConversionError> {
    let decoder = value.decoder();
    let sender = decode!(decoder, value.sender)?;
    let note_type = proto::note::NoteType::try_from(value.note_type)
        .map_err(|_| ConversionError::message("enum variant discriminant out of range"))?
        .try_into()
        .context("note_type")?;
    let tag = NoteTag::new(value.tag);
    Ok(PartialNoteMetadata::new(sender, note_type).with_tag(tag))
}

/// Decodes a serialized [`NoteAttachments`] payload. Empty bytes are treated as an empty collection
/// so that proto3's default value round-trips cleanly.
fn decode_attachments(bytes: &[u8]) -> Result<NoteAttachments, ConversionError> {
    if bytes.is_empty() {
        Ok(NoteAttachments::empty())
    } else {
        NoteAttachments::decode_bytes(bytes, "NoteAttachments")
    }
}
