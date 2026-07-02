use miden_node_proto::generated as proto;
use miden_node_utils::tracing::miden_instrument;
use tracing::debug;

use super::{RPC_LIMITS, RpcService};
use crate::{COMPONENT, LOG_TARGET};

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

    #[miden_instrument(
        target = COMPONENT,
        name = "get_limits",
        skip_all,
        err,
    )]
    async fn handle(&self, _request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: LOG_TARGET, "Getting limits");

        Ok(RPC_LIMITS.clone())
    }
}
