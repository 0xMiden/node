use std::sync::atomic::Ordering;

use miden_node_proto::generated as grpc;

use super::ValidatorService;

#[tonic::async_trait]
impl grpc::server::miden_validator_v1_validator_service::Status for ValidatorService {
    type Input = ();
    type Output = ();

    async fn full(
        &self,
        _request: tonic::Request<grpc::miden::validator::v1::StatusRequest>,
    ) -> tonic::Result<grpc::miden::validator::v1::StatusResponse> {
        // Unlike the other RPCs, status stays available during a backup so operators can observe
        // the validator. A failed read means a backup subscription holds the exclusive lock.
        let status = match self.serve_lock.try_read() {
            Ok(_guard) => "OK",
            Err(_) => "BACKUP",
        };

        Ok(grpc::miden::validator::v1::StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: status.to_string(),
            chain_tip: self.committed_tip.borrow().as_u32(),
            validated_transactions_count: self.validated_transactions_count.load(Ordering::Relaxed),
            signed_blocks_count: self.signed_blocks_count.load(Ordering::Relaxed),
        })
    }

    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        unimplemented!()
    }

    fn decode(_request: grpc::miden::validator::v1::StatusRequest) -> tonic::Result<Self::Input> {
        unimplemented!()
    }

    fn encode(_output: Self::Output) -> tonic::Result<grpc::miden::validator::v1::StatusResponse> {
        unimplemented!()
    }
}
