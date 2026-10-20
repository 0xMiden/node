//! Test to verify the `GrpcError` macro generates correct code

use thiserror::Error;

use crate::errors::GrpcError;

#[derive(Debug, Error, GrpcError)]
pub enum TestError {
    #[error("internal error 1")]
    #[grpc(internal)]
    InternalError1,

    #[error("client error 1")]
    ClientError1,

    #[error("internal error 2")]
    #[grpc(internal)]
    InternalError2,

    #[error("client error 2")]
    ClientError2,

    #[error("client error 3")]
    ClientError3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_mapped() {
        // Test that all variants map correctly
        assert_eq!(TestError::InternalError1.api_error(), TestErrorGrpcError::Internal);
        assert_eq!(TestError::ClientError1.api_error(), TestErrorGrpcError::ClientError1);
        assert_eq!(TestError::InternalError2.api_error(), TestErrorGrpcError::Internal);
        assert_eq!(TestError::ClientError2.api_error(), TestErrorGrpcError::ClientError2);
        assert_eq!(TestError::ClientError3.api_error(), TestErrorGrpcError::ClientError3);
    }

    #[test]
    fn test_grpc_error_codes() {
        // Verify the discriminant values
        assert_eq!(TestErrorGrpcError::Internal.api_code(), 0);
        assert_eq!(TestErrorGrpcError::ClientError1.api_code(), 1);
        assert_eq!(TestErrorGrpcError::ClientError2.api_code(), 2);
        assert_eq!(TestErrorGrpcError::ClientError3.api_code(), 3);
    }

    #[test]
    fn test_is_internal() {
        assert!(TestErrorGrpcError::Internal.is_internal());
        assert!(!TestErrorGrpcError::ClientError1.is_internal());
        assert!(!TestErrorGrpcError::ClientError2.is_internal());
        assert!(!TestErrorGrpcError::ClientError3.is_internal());
    }

    #[test]
    fn test_tonic_status_conversion() {
        // Test that the automatic From<Error> for tonic::Status implementation works
        let internal_status: tonic::Status = TestError::InternalError1.into();
        assert_eq!(internal_status.code(), tonic::Code::Internal);
        assert_eq!(internal_status.message(), "Internal error");

        let client_status: tonic::Status = TestError::ClientError1.into();
        assert_eq!(client_status.code(), tonic::Code::InvalidArgument);
        assert_eq!(client_status.message(), "client error 1");
    }
}
