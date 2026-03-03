use proto::worker_status_api_server::WorkerStatusApiServer;
use tonic::{Request, Response, Status};

use crate::generated::worker_status_api_server::WorkerStatusApi;
use crate::generated::{self as proto};
use crate::server::proof_kind::ProofKind;

pub struct StatusService {
    kind: ProofKind,
}

impl StatusService {
    pub fn new(kind: ProofKind) -> WorkerStatusApiServer<Self> {
        WorkerStatusApiServer::new(Self { kind })
    }
}

#[async_trait::async_trait]
impl WorkerStatusApi for StatusService {
    async fn status(&self, _: Request<()>) -> Result<Response<proto::WorkerStatus>, Status> {
        Ok(Response::new(proto::WorkerStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_proof_type: self.kind as i32,
        }))
    }
}
