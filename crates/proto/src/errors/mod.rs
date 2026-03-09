use std::any::type_name;

// Re-export the GrpcError derive macro for convenience
pub use miden_node_grpc_error_macro::GrpcError;
use miden_protocol::utils::DeserializationError;
use thiserror::Error;

// Re-export per-domain conversion errors
pub use crate::domain::account::AccountConversionError;
pub use crate::domain::batch::BatchConversionError;
pub use crate::domain::block::BlockConversionError;
pub use crate::domain::digest::DigestConversionError;
pub use crate::domain::mempool::MempoolConversionError;
pub use crate::domain::merkle::MerkleConversionError;
pub use crate::domain::note::NoteConversionError;
pub use crate::domain::nullifier::NullifierConversionError;
pub use crate::domain::transaction::TransactionConversionError;

#[cfg(test)]
mod test_macro;

// SHARED PROTO CONVERSION ERROR
// ================================================================================================

/// Shared error variants common to all protobuf conversions.
#[derive(Debug, Error)]
pub enum ProtoConversionError {
    #[error("field `{entity}::{field_name}` is missing")]
    MissingField {
        entity: &'static str,
        field_name: &'static str,
    },
    #[error("failed to deserialize {entity}")]
    DeserializationError {
        entity: &'static str,
        source: DeserializationError,
    },
}

impl ProtoConversionError {
    pub fn deserialization_error(entity: &'static str, source: DeserializationError) -> Self {
        Self::DeserializationError { entity, source }
    }
}

impl From<ProtoConversionError> for tonic::Status {
    fn from(value: ProtoConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}

pub trait MissingFieldHelper {
    fn missing_field(field_name: &'static str) -> ProtoConversionError;
}

impl<T: prost::Message> MissingFieldHelper for T {
    fn missing_field(field_name: &'static str) -> ProtoConversionError {
        ProtoConversionError::MissingField { entity: type_name::<T>(), field_name }
    }
}

// CONVERSION ERROR (WRAPPER)
// ================================================================================================

/// Union error type that wraps all per-domain conversion errors.
///
/// This preserves backward compatibility for downstream crates that use `#[from] ConversionError`.
/// Prefer using the domain-specific error types (e.g. `DigestConversionError`,
/// `AccountConversionError`) at conversion boundaries.
#[derive(Debug, Error)]
pub enum ConversionError {
    #[error(transparent)]
    Digest(#[from] DigestConversionError),
    #[error(transparent)]
    Account(#[from] AccountConversionError),
    #[error(transparent)]
    Note(#[from] NoteConversionError),
    #[error(transparent)]
    Block(#[from] BlockConversionError),
    #[error(transparent)]
    Merkle(#[from] MerkleConversionError),
    #[error(transparent)]
    Nullifier(#[from] NullifierConversionError),
    #[error(transparent)]
    Transaction(#[from] TransactionConversionError),
    #[error(transparent)]
    Batch(#[from] BatchConversionError),
    #[error(transparent)]
    Mempool(#[from] MempoolConversionError),
    #[error(transparent)]
    Proto(#[from] ProtoConversionError),
}

impl ConversionError {
    pub fn deserialization_error(entity: &'static str, source: DeserializationError) -> Self {
        Self::Proto(ProtoConversionError::deserialization_error(entity, source))
    }
}

impl From<ConversionError> for tonic::Status {
    fn from(value: ConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}
