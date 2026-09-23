use miden_node_block_producer::{BlockProducerStatus, MempoolStats};
use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};

use super::{ProtoMempoolStats, Request, RpcBackend, RpcService};
use crate::{COMPONENT, LOG_TARGET};

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

    #[miden_instrument(
        target = COMPONENT,
        name = "status",
        err,
    )]
    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let block_producer_status = match &self.backend {
            RpcBackend::Sequencer { block_producer, .. } => {
                Some(block_producer_status_to_proto(block_producer.status().await))
            },
            RpcBackend::FullNode { source_rpc, .. } => source_rpc
                .as_ref()
                .clone()
                .status(Request::new(()))
                .await
                .ok()
                .and_then(|response| response.into_inner().block_producer),
        };

        debug!(target: LOG_TARGET, "Getting status");

        Ok(proto::rpc::RpcStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            chain_tip: self.state.committed_tip().as_u32(),
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

// HELPERS
// ================================================================================================

fn block_producer_status_to_proto(status: BlockProducerStatus) -> proto::rpc::BlockProducerStatus {
    proto::rpc::BlockProducerStatus {
        version: status.version,
        status: status.status,
        chain_tip: status.chain_tip.as_u32(),
        mempool_stats: Some(block_producer_mempool_stats_to_proto(status.mempool_stats)),
    }
}

fn block_producer_mempool_stats_to_proto(stats: MempoolStats) -> proto::rpc::MempoolStats {
    proto::rpc::MempoolStats {
        unbatched_transactions: stats.unbatched_transactions,
        proposed_batches: stats.proposed_batches,
        proven_batches: stats.proven_batches,
        uncommitted_transactions: stats.uncommitted_transactions,
    }
}
