use std::sync::atomic::Ordering;

use miden_node_proto::generated as grpc;

use super::ValidatorService;

#[tonic::async_trait]
impl grpc::server::validator_api::Status for ValidatorService {
    type Input = ();
    type Output = ();

    async fn full(
        &self,
        _request: tonic::Request<()>,
    ) -> tonic::Result<grpc::validator::ValidatorStatus> {
        // Reject requests while a backup subscription is streaming. Fails fast rather than blocking.
        let _guard = self.serve_lock.try_read().map_err(|_| {
            tonic::Status::resource_exhausted("validator is busy streaming a backup")
        })?;

        Ok(grpc::validator::ValidatorStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "OK".to_string(),
            chain_tip: self.committed_tip.borrow().as_u32(),
            validated_transactions_count: self.validated_transactions_count.load(Ordering::Relaxed),
            signed_blocks_count: self.signed_blocks_count.load(Ordering::Relaxed),
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
