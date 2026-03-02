use miden_node_proto::generated::server::validator_api::Status;
use miden_node_proto::server::{GrpcEncode, GrpcInterface};

use crate::server::ValidatorServer;

#[tonic::async_trait]
impl miden_node_proto::server::GrpcUnary<Status> for ValidatorServer {
    type Input = ();
    type Output = Output;

    async fn handle(&self, _input: Self::Input) -> tonic::Result<Self::Output> {
        Ok(Output)
    }
}

pub struct Output;

impl GrpcEncode<<Status as GrpcInterface>::Response> for Output {
    fn encode(self) -> Result<<Status as GrpcInterface>::Response, tonic::Status> {
        Ok(miden_node_proto::generated::validator::ValidatorStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "OK".to_string(),
        })
    }
}
