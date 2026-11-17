use std::time::Duration;

use miden_node_block_producer::{BlockProducerStatus, MempoolStats};
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::miden::node::v1::BlockProducerStatus as ProtoBlockProducerStatus;
use miden_node_tracing::{debug, instrument};
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::{ProtoMempoolStats, Request, RpcBackend, RpcService};

const UPSTREAM_STATUS_TTL: Duration = Duration::from_secs(5);

/// Caches the upstream sequencer status, including failed lookups.
///
/// Refreshes share an async lock so concurrent probes make only one upstream request. Local node
/// state is read separately on every request, so its chain tip can be ahead of the cached upstream
/// height.
#[derive(Default)]
pub(super) struct UpstreamStatusCache(Mutex<Option<CachedStatus>>);

struct CachedStatus {
    expires_at: Instant,
    status: Option<ProtoBlockProducerStatus>,
}

impl UpstreamStatusCache {
    async fn get(&self, source_rpc: &RpcClient) -> Option<ProtoBlockProducerStatus> {
        let mut cached = self.0.lock().await;
        if let Some(cached) = cached.as_ref()
            && cached.expires_at > Instant::now()
        {
            return cached.status.clone();
        }

        let status = source_rpc
            .clone()
            .status(Request::new(proto::miden::node::v1::StatusRequest {}))
            .await
            .ok()
            .and_then(|response| response.into_inner().block_producer);
        *cached = Some(CachedStatus {
            expires_at: Instant::now() + UPSTREAM_STATUS_TTL,
            status: status.clone(),
        });
        status
    }
}

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::Status for RpcService {
    type Input = ();
    type Output = proto::miden::node::v1::StatusResponse;

    fn decode(_request: proto::miden::node::v1::StatusRequest) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::miden::node::v1::StatusResponse> {
        Ok(output)
    }

    #[instrument(name = "status", level = "debug")]
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
            RpcBackend::FullNode { source_rpc, .. } => self.upstream_status.get(source_rpc).await,
        };

        debug!("Getting status");

        Ok(proto::miden::node::v1::StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            chain_tip: self.state.committed_tip().as_u32(),
            block_producer: block_producer_status.or(Some(
                proto::miden::node::v1::BlockProducerStatus {
                    status: "unreachable".to_string(),
                    version: "-".to_string(),
                    chain_tip: 0,
                    mempool_stats: Some(ProtoMempoolStats::default()),
                },
            )),
            genesis_commitment: self.genesis_commitment.map(Into::into),
        })
    }
}

// HELPERS
// ================================================================================================

fn block_producer_status_to_proto(
    status: BlockProducerStatus,
) -> proto::miden::node::v1::BlockProducerStatus {
    proto::miden::node::v1::BlockProducerStatus {
        version: status.version,
        status: status.status,
        chain_tip: status.chain_tip.as_u32(),
        mempool_stats: Some(block_producer_mempool_stats_to_proto(status.mempool_stats)),
    }
}

fn block_producer_mempool_stats_to_proto(
    stats: MempoolStats,
) -> proto::miden::node::v1::MempoolStats {
    proto::miden::node::v1::MempoolStats {
        unbatched_transactions: stats.unbatched_transactions,
        proposed_batches: stats.proposed_batches,
        proven_batches: stats.proven_batches,
        uncommitted_transactions: stats.uncommitted_transactions,
    }
}
