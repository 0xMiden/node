use std::marker::PhantomData;

use miden_protocol::utils::serde::Deserializable;

mod utils;
pub use utils::*;

use crate::errors::ConversionError;
// Re-export so callers can import from `conv`.
pub use crate::errors::ConversionResultExt;

// GRPC STRUCT DECODER
// ================================================================================================

/// Zero-cost struct decoder that captures the parent proto message type.
///
/// Created via [`GrpcDecodeExt::decoder`] which infers the parent type from the value:
///
/// ```rust,ignore
/// // Before:
/// let body = block.body.try_convert_field::<proto::SignedBlock>("body")?;
/// let header = block.header.try_convert_field::<proto::SignedBlock>("header")?;
///
/// // After:
/// let decoder = block.decoder();
/// let body = decode!(decoder, block.body);
/// let header = decode!(decoder, block.header);
/// ```
pub struct GrpcStructDecoder<M>(PhantomData<M>);

impl<M: prost::Message> Default for GrpcStructDecoder<M> {
    /// Create a decoder for the given parent message type directly.
    ///
    /// Prefer [`GrpcDecodeExt::decoder`] when a value of type `M` is available, as it infers
    /// the type automatically.
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<M: prost::Message> GrpcStructDecoder<M> {
    /// Decode a required optional field: checks for `None`, converts via `TryInto`, and adds field
    /// context on error.
    pub fn decode_field<T, F>(
        &self,
        name: &'static str,
        value: Option<T>,
    ) -> Result<F, ConversionError>
    where
        T: TryInto<F>,
        T::Error: Into<ConversionError>,
    {
        value
            .ok_or_else(|| ConversionError::missing_field::<M>(name))?
            .try_into()
            .context(name)
    }
}

/// Extension trait on [`prost::Message`] types to create a [`GrpcStructDecoder`] with the parent
/// type inferred from the value.
pub trait GrpcDecodeExt: prost::Message + Sized {
    /// Create a decoder that uses `Self` as the parent message type for error reporting.
    fn decoder(&self) -> GrpcStructDecoder<Self> {
        GrpcStructDecoder(PhantomData)
    }
}

impl<T: prost::Message> GrpcDecodeExt for T {}

/// Decodes a required optional field from a protobuf message using the message's decoder.
///
/// Uses `stringify!` to automatically derive the field name for error reporting, avoiding
/// the duplication between a string literal and the field access.
///
/// Has two forms:
/// - `decode!(decoder, msg.field)` — expands to `decoder.decode_field("field", msg.field)`. Use
///   when accessing a field directly on the message value.
/// - `decode!(decoder, field)` — expands to `decoder.decode_field("field", field)`. Use after
///   destructuring the message, when the field is a bare identifier.
///
/// # Usage
///
/// ```ignore
/// let decoder = value.decoder();
/// // With a field access:
/// let sender = decode!(decoder, value.sender)?;
///
/// // With a bare identifier (after destructuring):
/// let Proto { sender, .. } = value;
/// let sender = decode!(decoder, sender)?;
///
/// // Without `?` to return the Result directly:
/// decode!(decoder, value.id)
/// ```
#[macro_export]
macro_rules! decode {
    ($decoder:ident, $msg:ident . $field:ident) => {
        $decoder.decode_field(stringify!($field), $msg.$field)
    };
    ($decoder:ident, $field:ident) => {
        $decoder.decode_field(stringify!($field), $field)
    };
}

// BYTE DESERIALIZATION EXTENSION TRAIT
// ================================================================================================

/// Extension trait on [`Deserializable`](miden_protocol::utils::Deserializable) types to
/// deserialize from bytes and wrap errors as [`ConversionError`].
///
/// This removes the boilerplate of calling `T::read_from_bytes(&bytes)` followed by
/// `.map_err(|source| ConversionError::deserialization("T", source))`:
///
/// ```rust,ignore
/// // Before:
/// BlockBody::read_from_bytes(&value.block_body)
///     .map_err(|source| ConversionError::deserialization("BlockBody", source))
///
/// // After:
/// BlockBody::decode_bytes(&value.block_body, "BlockBody")
/// ```
pub trait DecodeBytesExt: Deserializable {
    /// Deserialize from bytes, wrapping any error as a [`ConversionError`].
    fn decode_bytes(bytes: &[u8], entity: &'static str) -> Result<Self, ConversionError> {
        Self::read_from_bytes(bytes)
            .map_err(|source| ConversionError::deserialization(entity, source))
    }
}

impl<T: Deserializable> DecodeBytesExt for T {}

#[cfg(test)]
mod tests {
    use miden_protocol::Felt;

    use super::*;
    use crate::generated::primitives::Digest;

    /// Simulates a deeply nested conversion where each layer adds its field context.
    fn inner_conversion() -> Result<(), ConversionError> {
        Err(ConversionError::message("value is not in range 0..MODULUS"))
    }

    fn outer_conversion() -> Result<(), ConversionError> {
        inner_conversion().context("account_root").context("header")
    }

    #[test]
    fn test_context_builds_dotted_field_path() {
        let err = outer_conversion().unwrap_err();
        assert_eq!(err.to_string(), "header.account_root: value is not in range 0..MODULUS");
    }

    #[test]
    fn test_context_single_field() {
        let err = inner_conversion().context("nullifier").unwrap_err();
        assert_eq!(err.to_string(), "nullifier: value is not in range 0..MODULUS");
    }

    #[test]
    fn test_context_deep_nesting() {
        let err = outer_conversion().context("block").context("response").unwrap_err();
        assert_eq!(
            err.to_string(),
            "response.block.header.account_root: value is not in range 0..MODULUS"
        );
    }

    #[test]
    fn test_no_context_shows_source_only() {
        let err = inner_conversion().unwrap_err();
        assert_eq!(err.to_string(), "value is not in range 0..MODULUS");
    }

    #[test]
    fn test_context_on_external_error_type() {
        let result: Result<u8, std::num::TryFromIntError> = u8::try_from(256u16);
        let err = result.context("fee_amount").unwrap_err();
        assert!(err.to_string().starts_with("fee_amount: "), "expected field prefix, got: {err}",);
    }

    #[test]
    fn test_decode_field_missing() {
        let decoder = GrpcStructDecoder::<crate::generated::blockchain::BlockHeader>::default();
        let account_root: Option<Digest> = None;
        let result: Result<[Felt; 4], _> = decode!(decoder, account_root);
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("account_root") && err.to_string().contains("missing"),
            "expected missing field error, got: {err}",
        );
    }

    #[test]
    fn test_decode_field_conversion_error() {
        let decoder = GrpcStructDecoder::<crate::generated::blockchain::BlockHeader>::default();
        // Create a digest with an out-of-range value.
        let account_root = Some(Digest { d0: u64::MAX, d1: 0, d2: 0, d3: 0 });
        let result: Result<[Felt; 4], _> = decode!(decoder, account_root);
        let err = result.unwrap_err();
        assert!(
            err.to_string().starts_with("account_root: "),
            "expected field prefix, got: {err}",
        );
    }
}
