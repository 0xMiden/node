use std::any::type_name;
use std::num::TryFromIntError;

// Re-export the GrpcError derive macro for convenience
pub use miden_node_grpc_error_macro::GrpcError;
use miden_protocol::crypto::merkle::smt::{SmtLeafError, SmtProofError};
use miden_protocol::errors::{AccountError, AssetError, FeeError, NoteError, StorageSlotNameError};
use miden_protocol::utils::DeserializationError;
use thiserror::Error;

use crate::domain::note::NetworkNoteError;

#[cfg(test)]
mod test_macro;

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("asset error")]
    AssetError(#[from] AssetError),
    #[error("account code missing")]
    AccountCodeMissing,
    #[error("account error")]
    AccountError(#[from] AccountError),
    #[error("fee parameters error")]
    FeeError(#[from] FeeError),
    #[error("hex error")]
    HexError(#[from] hex::FromHexError),
    #[error("note error")]
    NoteError(#[from] NoteError),
    #[error("network note error")]
    NetworkNoteError(#[from] NetworkNoteError),
    #[error("SMT leaf error")]
    SmtLeafError(#[from] SmtLeafError),
    #[error("SMT proof error")]
    SmtProofError(#[from] SmtProofError),
    #[error("storage slot name error")]
    StorageSlotNameError(#[from] StorageSlotNameError),
    #[error("integer conversion error: {0}")]
    TryFromIntError(#[from] TryFromIntError),
    #[error("too much data, expected {expected}, got {got}")]
    TooMuchData { expected: usize, got: usize },
    #[error("not enough data, expected {expected}, got {got}")]
    InsufficientData { expected: usize, got: usize },
    #[error("value is not in the range 0..MODULUS")]
    NotAValidFelt,
    #[error("merkle error")]
    MerkleError(#[from] miden_protocol::crypto::merkle::MerkleError),
    #[error("field `{entity}::{field_name}` is missing")]
    MissingFieldInProtobufRepresentation {
        entity: &'static str,
        field_name: &'static str,
    },
    #[error("failed to deserialize {entity}")]
    DeserializationError {
        entity: &'static str,
        source: DeserializationError,
    },
    #[error("enum variant discriminant out of range")]
    EnumDiscriminantOutOfRange,
}

impl ConversionError {
    pub fn deserialization_error(entity: &'static str, source: DeserializationError) -> Self {
        Self::DeserializationError { entity, source }
    }
}

pub trait MissingFieldHelper {
    fn missing_field(field_name: &'static str) -> ConversionError;
}

impl<T: prost::Message> MissingFieldHelper for T {
    fn missing_field(field_name: &'static str) -> ConversionError {
        ConversionError::MissingFieldInProtobufRepresentation {
            entity: type_name::<T>(),
            field_name,
        }
    }
}

impl From<ConversionError> for tonic::Status {
    fn from(value: ConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}
