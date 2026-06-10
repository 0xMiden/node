use miden_node_proto::generated as proto;
use tracing::debug;

use super::{COMPONENT, RPC_LIMITS, RpcService};

#[tonic::async_trait]
impl proto::server::rpc_api::GetLimits for RpcService {
    type Input = ();
    type Output = proto::rpc::RpcLimits;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::RpcLimits> {
        Ok(output)
    }

    async fn handle(&self, _request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: COMPONENT, request = ?());

        Ok(RPC_LIMITS.clone())
    }
}
