use miden_node_block_producer::{BlockProducerStatus, MempoolStats};
use miden_node_proto::generated as proto;
use miden_node_utils::tracing::miden_instrument;
use tracing::debug;

use super::{Finality, ProtoMempoolStats, Request, RpcMode, RpcService};
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
        skip_all,
        err,
    )]
    async fn handle(&self, _request: Self::Input) -> tonic::Result<Self::Output> {
        let block_producer_status = match &self.mode {
            RpcMode::Sequencer { block_producer, .. } => {
                Some(block_producer_status_to_proto(block_producer.status().await))
            },
            RpcMode::FullNode { source_rpc, .. } => source_rpc
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
    }
}
