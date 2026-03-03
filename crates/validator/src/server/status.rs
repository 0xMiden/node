use miden_node_proto::generated as grpc;

use crate::server::ValidatorServer;

#[tonic::async_trait]
impl grpc::server::validator_api::Status for ValidatorServer {
    type Input = ();
    type Output = ();

    async fn full(&self, _request: ()) -> tonic::Result<grpc::validator::ValidatorStatus> {
        Ok(grpc::validator::ValidatorStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "OK".to_string(),
        })
    }

    async fn handle(&self, _input: Self::Input) -> tonic::Result<Self::Output> {
        unimplemented!()
    }

    fn decode(_request: ()) -> tonic::Result<Self::Input> {
        unimplemented!()
    }

    fn encode(_output: Self::Output) -> tonic::Result<grpc::validator::ValidatorStatus> {
        unimplemented!()
    }
}
