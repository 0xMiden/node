use miden_node_proto::generated as proto;
use tracing::debug;

use super::{
    COMPONENT,
    Finality,
    ProtoMempoolStats,
    Request,
    RpcMode,
    RpcService,
    block_producer_status_to_proto,
};

#[tonic::async_trait]
impl proto::server::rpc_api::Status for RpcService {
    type Input = ();
    type Output = proto::rpc::RpcStatus;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::RpcStatus> {
        Ok(output)
    }

    async fn handle(&self, _request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: COMPONENT, request = ?());

        let block_producer_status = match &self.mode {
            RpcMode::Sequencer { block_producer, .. } => {
                Some(block_producer_status_to_proto(block_producer.status().await))
            },
            RpcMode::FullNode { source_rpc } => source_rpc
                .as_ref()
                .clone()
                .status(Request::new(()))
                .await
                .ok()
                .and_then(|response| response.into_inner().block_producer),
        };

        Ok(proto::rpc::RpcStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            chain_tip: self.store.chain_tip(Finality::Committed).await.as_u32(),
            block_producer: block_producer_status.or(Some(proto::rpc::BlockProducerStatus {
                status: "unreachable".to_string(),
                version: "-".to_string(),
                chain_tip: 0,
                mempool_stats: Some(ProtoMempoolStats::default()),
            })),
            genesis_commitment: self.genesis_commitment.map(Into::into),
        })
    }
}
