use std::any::type_name;
use std::fmt;
use std::marker::PhantomData;

// Re-export the GrpcError derive macro for convenience
pub use miden_node_grpc_error_macro::{GrpcError, grpc_decode};
use miden_protocol::utils::DeserializationError;

#[cfg(test)]
mod test_grpc_decode;
#[cfg(test)]
mod test_macro;

// CONVERSION ERROR
// ================================================================================================

/// Opaque error for protobuf-to-domain conversions.
///
/// Captures an underlying error plus an optional field path stack that describes which nested
/// field caused the error (e.g. `"block.header.account_root: value is not in range 0..MODULUS"`).
///
/// Always maps to [`tonic::Status::invalid_argument()`].
#[derive(Debug)]
pub struct ConversionError {
    path: Vec<&'static str>,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl ConversionError {
    /// Create a new `ConversionError` wrapping any error source.
    pub fn new(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            path: Vec::new(),
            source: Box::new(source),
        }
    }

    /// Add field context to the error path.
    ///
    /// Called from inner to outer, so the path accumulates in reverse
    /// (outermost field pushed last).
    ///
    /// Use this to annotate errors from `try_into()` / `try_from()` where the underlying
    /// error has no knowledge of which field it originated from. Do not use it with
    /// [`missing_field`](Self::missing_field) which already embeds the field name in its
    /// message.
    #[must_use]
    pub fn context(mut self, field: &'static str) -> Self {
        self.path.push(field);
        self
    }

    /// Create a "missing field" error for a protobuf message type `T`.
    pub fn missing_field<T: prost::Message>(field_name: &'static str) -> Self {
        Self {
            path: Vec::new(),
            source: Box::new(MissingFieldError { entity: type_name::<T>(), field_name }),
        }
    }

    /// Create a deserialization error for a named entity.
    pub fn deserialization(entity: &'static str, source: DeserializationError) -> Self {
        Self {
            path: Vec::new(),
            source: Box::new(DeserializationErrorWrapper { entity, source }),
        }
    }

    /// Create a `ConversionError` from an ad-hoc error message.
    pub fn message(msg: impl Into<String>) -> Self {
        Self {
            path: Vec::new(),
            source: Box::new(StringError(msg.into())),
        }
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.path.is_empty() {
            // Path was pushed inner-to-outer, so reverse for display.
            for (i, segment) in self.path.iter().rev().enumerate() {
                if i > 0 {
                    f.write_str(".")?;
                }
                f.write_str(segment)?;
            }
            f.write_str(": ")?;
        }
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for ConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

impl From<ConversionError> for tonic::Status {
    fn from(value: ConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}

// INTERNAL HELPER ERROR TYPES
// ================================================================================================

#[derive(Debug)]
struct MissingFieldError {
    entity: &'static str,
    field_name: &'static str,
}

impl fmt::Display for MissingFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "field `{}::{}` is missing", self.entity, self.field_name)
    }
}

impl std::error::Error for MissingFieldError {}

#[derive(Debug)]
struct DeserializationErrorWrapper {
    entity: &'static str,
    source: DeserializationError,
}

impl fmt::Display for DeserializationErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to deserialize {}: {}", self.entity, self.source)
    }
}

impl std::error::Error for DeserializationErrorWrapper {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StringError {}

// CONVERSION RESULT EXTENSION TRAIT
// ================================================================================================

/// Extension trait to ergonomically add field context to [`ConversionError`] results.
///
/// This makes it easy to inject field names into the error path at each `?` site:
///
/// ```rust,ignore
/// let account_root = value.account_root
///     .ok_or(ConversionError::missing_field::<proto::BlockHeader>("account_root"))?
///     .try_into()
///     .context("account_root")?;
/// ```
///
/// The context stacks automatically through nested conversions, producing error paths like
/// `"header.account_root: value is not in range 0..MODULUS"`.
pub trait ConversionResultExt<T> {
    /// Add field context to the error, wrapping it in a [`ConversionError`] if needed.
    fn context(self, field: &'static str) -> Result<T, ConversionError>;
}

impl<T, E: Into<ConversionError>> ConversionResultExt<T> for Result<T, E> {
    fn context(self, field: &'static str) -> Result<T, ConversionError> {
        self.map_err(|e| e.into().context(field))
    }
}

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
/// let body = decoder.decode_field("body", block.body)?;
/// let header = decoder.decode_field("header", block.header)?;
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
    /// Decode a required optional field: checks for `None`, converts via `TryInto`, and adds
    /// field context on error.
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
pub trait DecodeBytesExt: miden_protocol::utils::Deserializable {
    /// Deserialize from bytes, wrapping any error as a [`ConversionError`].
    fn decode_bytes(bytes: &[u8], entity: &'static str) -> Result<Self, ConversionError> {
        Self::read_from_bytes(bytes)
            .map_err(|source| ConversionError::deserialization(entity, source))
    }
}

impl<T: miden_protocol::utils::Deserializable> DecodeBytesExt for T {}

// FROM IMPLS FOR EXTERNAL ERROR TYPES
// ================================================================================================

macro_rules! impl_from_for_conversion_error {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for ConversionError {
                fn from(e: $ty) -> Self {
                    Self::new(e)
                }
            }
        )*
    };
}

impl_from_for_conversion_error!(
    hex::FromHexError,
    miden_protocol::errors::AccountError,
    miden_protocol::errors::AssetError,
    miden_protocol::errors::AssetVaultError,
    miden_protocol::errors::FeeError,
    miden_protocol::errors::NoteError,
    miden_protocol::errors::StorageSlotNameError,
    miden_protocol::crypto::merkle::MerkleError,
    miden_protocol::crypto::merkle::smt::SmtLeafError,
    miden_protocol::crypto::merkle::smt::SmtProofError,
    miden_standards::note::NetworkAccountTargetError,
    std::num::TryFromIntError,
    DeserializationError,
);

#[cfg(test)]
mod tests {
    use super::*;

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
        use miden_protocol::Felt;

        use crate::generated::primitives::Digest;

        let decoder = GrpcStructDecoder::<crate::generated::blockchain::BlockHeader>::default();
        let field: Option<Digest> = None;
        let result: Result<[Felt; 4], _> = decoder.decode_field("account_root", field);
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("account_root") && err.to_string().contains("missing"),
            "expected missing field error, got: {err}",
        );
    }

    #[test]
    fn test_decode_field_conversion_error() {
        use miden_protocol::Felt;

        use crate::generated::primitives::Digest;

        let decoder = GrpcStructDecoder::<crate::generated::blockchain::BlockHeader>::default();
        // Create a digest with an out-of-range value.
        let bad_digest = Digest { d0: u64::MAX, d1: 0, d2: 0, d3: 0 };
        let result: Result<[Felt; 4], _> = decoder.decode_field("account_root", Some(bad_digest));
        let err = result.unwrap_err();
        assert!(
            err.to_string().starts_with("account_root: "),
            "expected field prefix, got: {err}",
        );
    }
}
