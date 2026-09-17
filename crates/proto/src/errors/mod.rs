pub use miden_node_grpc_error_macro::GrpcError;
pub use miden_protobuf::{ConversionError, ConversionResultExt};

#[cfg(test)]
mod test_macro;

/// Map a protobuf conversion error to an invalid argument status. Retain the full source chain.
pub fn conversion_error_to_status(error: ConversionError) -> tonic::Status {
    error.into_status()
}
