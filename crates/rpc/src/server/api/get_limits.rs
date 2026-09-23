use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};

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
        err,
    )]
    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        debug!(target: LOG_TARGET, "Getting limits");

        Ok(RPC_LIMITS.clone())
    }
}
