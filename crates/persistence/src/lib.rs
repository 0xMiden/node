//! Protobuf codecs for structured database values and binary files.

mod collections;
mod error;
pub mod generated;
mod protocol;

pub use error::PersistenceError;
pub use miden_protobuf;
pub use prost;

/// Defines the stored representation and domain validation for one type.
pub trait ProtobufValue: Sized {
    /// The protobuf message stored for this type.
    type Message: prost::Message + Default;
    /// Builds the stored protobuf message.
    fn to_proto(&self) -> Self::Message;
    /// Builds the domain value and checks its construction constraints.
    fn from_proto(message: Self::Message) -> Result<Self, PersistenceError>;
}

/// Encodes a structured value as its protobuf message.
pub fn encode<T: ProtobufValue>(value: &T) -> Vec<u8> {
    prost::Message::encode_to_vec(&value.to_proto())
}

/// Decodes a stored message and applies its domain construction checks.
pub fn decode<T: ProtobufValue>(bytes: &[u8]) -> Result<T, PersistenceError> {
    let message = <T::Message as prost::Message>::decode(bytes)?;
    T::from_proto(message)
}

/// Rejects an unsupported file format version.
pub fn check_version(format: &'static str, version: u32) -> Result<(), PersistenceError> {
    if version != 1 {
        return Err(PersistenceError::UnsupportedVersion { format, version });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
