use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};

use super::{RPC_LIMITS, RpcService};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::GetLimits for RpcService {
    type Input = ();
    type Output = proto::miden::node::v1::GetLimitsResponse;

    fn decode(_request: proto::miden::node::v1::GetLimitsRequest) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::miden::node::v1::GetLimitsResponse> {
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
