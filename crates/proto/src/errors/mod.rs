pub use miden_node_grpc_error_macro::GrpcError;
pub use miden_protobuf::{ConversionError, ConversionResultExt};

#[cfg(test)]
mod test_macro;

/// Map a protobuf conversion error to an invalid argument status.
#[expect(clippy::needless_pass_by_value, reason = "matches the Result::map_err signature")]
pub fn conversion_error_to_status(error: ConversionError) -> tonic::Status {
    tonic::Status::invalid_argument(error.to_string())
}
