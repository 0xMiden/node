use miden_protocol::Word;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{InputNoteCommitment, TransactionId};
use miden_protocol::utils::{Deserializable, Serializable};

use crate::errors::{ConversionError, ConversionResultExt, TryConvertFieldExt};
use crate::generated as proto;

// FROM TRANSACTION ID
// ================================================================================================

impl From<&TransactionId> for proto::primitives::Digest {
    fn from(value: &TransactionId) -> Self {
        value.as_word().into()
    }
}

impl From<TransactionId> for proto::primitives::Digest {
    fn from(value: TransactionId) -> Self {
        value.as_word().into()
    }
}

impl From<&TransactionId> for proto::transaction::TransactionId {
    fn from(value: &TransactionId) -> Self {
        proto::transaction::TransactionId { id: Some(value.into()) }
    }
}

impl From<TransactionId> for proto::transaction::TransactionId {
    fn from(value: TransactionId) -> Self {
        (&value).into()
    }
}

// INTO TRANSACTION ID
// ================================================================================================

impl TryFrom<proto::primitives::Digest> for TransactionId {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        let digest: Word = value.try_into()?;
        Ok(TransactionId::from_raw(digest))
    }
}

impl TryFrom<proto::transaction::TransactionId> for TransactionId {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::TransactionId) -> Result<Self, Self::Error> {
        value.id.try_convert_field::<proto::transaction::TransactionId>("id")
    }
}

// INPUT NOTE COMMITMENT
// ================================================================================================

impl From<InputNoteCommitment> for proto::transaction::InputNoteCommitment {
    fn from(value: InputNoteCommitment) -> Self {
        Self {
            nullifier: Some(value.nullifier().into()),
            header: value.header().cloned().map(Into::into),
        }
    }
}

impl TryFrom<proto::transaction::InputNoteCommitment> for InputNoteCommitment {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::InputNoteCommitment) -> Result<Self, Self::Error> {
        let nullifier: Nullifier = value
            .nullifier
            .try_convert_field::<proto::transaction::InputNoteCommitment>("nullifier")?;

        let header: Option<miden_protocol::note::NoteHeader> =
            value.header.map(TryInto::try_into).transpose().context("header")?;

        // TODO: https://github.com/0xMiden/node/issues/1783
        // InputNoteCommitment has private fields, so we reconstruct it via
        // serialization roundtrip using its Serializable/Deserializable impls.
        let mut bytes = Vec::new();
        nullifier.write_into(&mut bytes);
        header.write_into(&mut bytes);
        InputNoteCommitment::read_from_bytes(&bytes)
            .map_err(|err| ConversionError::deserialization("InputNoteCommitment", err))
    }
}
