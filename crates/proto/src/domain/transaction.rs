use miden_protocol::Word;
use miden_protocol::transaction::TransactionId;
use thiserror::Error;

use crate::domain::digest::DigestConversionError;
use crate::errors::{MissingFieldHelper, ProtoConversionError};
use crate::generated as proto;

// TRANSACTION CONVERSION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionConversionError {
    #[error(transparent)]
    Proto(#[from] ProtoConversionError),
    #[error(transparent)]
    Digest(#[from] DigestConversionError),
}

impl From<TransactionConversionError> for tonic::Status {
    fn from(value: TransactionConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}

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
    type Error = DigestConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        let digest: Word = value.try_into()?;
        Ok(TransactionId::from_raw(digest))
    }
}

impl TryFrom<proto::transaction::TransactionId> for TransactionId {
    type Error = TransactionConversionError;

    fn try_from(value: proto::transaction::TransactionId) -> Result<Self, Self::Error> {
        value
            .id
            .ok_or(proto::transaction::TransactionId::missing_field("id"))?
            .try_into()
            .map_err(TransactionConversionError::from)
    }
}
