/// A malformed protobuf message or invalid stored domain value.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("invalid persisted protobuf message")]
    Wire(#[from] prost::DecodeError),
    #[error("invalid persisted domain value")]
    Conversion(#[from] miden_protobuf::ConversionError),
    #[error("unsupported {format} version {version}; recreate this data with the current node")]
    UnsupportedVersion { format: &'static str, version: u32 },
}
