use miden_node_proto::generated as proto;
use miden_node_tracing::{debug_v2, instrument_v2};

use super::{RPC_LIMITS, RpcService};

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

    #[instrument_v2(name = "get_limits")]
    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        debug_v2!("Getting limits");

        Ok(RPC_LIMITS.clone())
    }
}
