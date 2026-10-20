use miden_node_proto::generated as grpc;

use crate::server::proof_kind::ProofKind;

pub struct StatusService {
    kind: ProofKind,
}

impl StatusService {
    pub fn new(kind: ProofKind) -> Self {
        Self { kind }
    }
}

#[tonic::async_trait]
impl grpc::server::miden_remote_prover_v1_worker_status_service::Status for StatusService {
    type Input = ();
    type Output = grpc::miden::remote_prover::v1::WorkerStatusResponse;

    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        Ok(grpc::miden::remote_prover::v1::WorkerStatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_proof_type: self.kind as i32,
        })
    }

    fn decode(
        _request: grpc::miden::remote_prover::v1::WorkerStatusRequest,
    ) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<grpc::miden::remote_prover::v1::WorkerStatusResponse> {
        Ok(output)
    }
}
