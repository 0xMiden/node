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
impl grpc::server::remote_prover_worker_status_api::Status for StatusService {
    type Input = ();
    type Output = ();

    async fn full(&self, _request: ()) -> tonic::Result<grpc::remote_prover::WorkerStatus> {
        Ok(grpc::remote_prover::WorkerStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_proof_type: self.kind as i32,
        })
    }

    async fn handle(&self, _input: Self::Input) -> tonic::Result<Self::Output> {
        unimplemented!()
    }

    fn decode(_request: ()) -> tonic::Result<Self::Input> {
        unimplemented!()
    }

    fn encode(_output: Self::Output) -> tonic::Result<grpc::remote_prover::WorkerStatus> {
        unimplemented!()
    }
}
