use miden_protobuf::{BuildUnchecked, ConversionError, DecodeMessage, Verify};
use miden_protocol::block::BlockSignatures;
use miden_protocol::note::{NoteAssets, NoteHeader};
use miden_protocol::transaction::InputNoteCommitment;

use crate::{PersistenceError, ProtobufValue, generated};

impl ProtobufValue for BlockSignatures {
    type Message = generated::BlockSignatures;
    fn to_proto(&self) -> Self::Message {
        Self::Message {
            signatures: self.as_signatures().iter().map(Into::into).collect(),
        }
    }
    fn from_proto(message: Self::Message) -> Result<Self, PersistenceError> {
        let signatures = message.decode_fields()?.signatures.verify_infallible();
        Self::new(signatures).map_err(|err| ConversionError::new(err).into())
    }
}
impl ProtobufValue for NoteAssets {
    type Message = generated::NoteAssets;
    fn to_proto(&self) -> Self::Message {
        Self::Message {
            assets: self.iter().map(Into::into).collect(),
        }
    }
    fn from_proto(message: Self::Message) -> Result<Self, PersistenceError> {
        let assets = message.decode_fields()?.assets.verify()?;
        Self::new(assets).map_err(|err| ConversionError::new(err).into())
    }
}
impl ProtobufValue for Vec<InputNoteCommitment> {
    type Message = generated::InputNoteCommitments;
    fn to_proto(&self) -> Self::Message {
        Self::Message {
            notes: self.iter().map(Into::into).collect(),
        }
    }
    fn from_proto(message: Self::Message) -> Result<Self, PersistenceError> {
        Ok(message.decode_fields()?.notes.build_unchecked()?)
    }
}
impl ProtobufValue for Vec<NoteHeader> {
    type Message = generated::NoteHeaders;
    fn to_proto(&self) -> Self::Message {
        Self::Message {
            notes: self.iter().copied().map(Into::into).collect(),
        }
    }
    fn from_proto(message: Self::Message) -> Result<Self, PersistenceError> {
        Ok(message.decode_fields()?.notes.verify()?)
    }
}
