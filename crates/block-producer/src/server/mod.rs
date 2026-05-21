use std::sync::Arc;

use anyhow::Context;
use futures::StreamExt;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_proto::generated::block_producer::api_server;
use miden_node_proto::generated::{self as proto};
use miden_node_proto_build::block_producer_api_descriptor;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::formatting::{format_input_notes, format_output_notes};
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::utils::serde::Deserializable;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::Status;
use tower_http::trace::TraceLayer;
use tracing::{debug, instrument};

use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::MempoolSubmissionError;
use crate::mempool::SharedMempool;
use crate::store::StoreClient;
use crate::{CACHED_MEMPOOL_STATS_UPDATE_INTERVAL, COMPONENT};

pub mod embedded;
pub mod remote;

#[cfg(test)]
mod tests;

pub use embedded::EmbeddedBlockProducer;
pub use remote::RemoteBlockProducer;

// BLOCK PRODUCER HANDLE
// ================================================================================================

/// A cloneable in-process handle to the block producer's core logic.
///
/// Holds the mempool, store, and cached stats. Both [`BlockProducerRpcServer`] and the embedded
/// sequencer's RPC use this handle — the server as its implementation backing, the sequencer to
/// submit transactions without a gRPC round-trip.
///
/// The outer [`Mutex`] around the mempool rate-limits concurrent submissions, giving the batch and
/// block builders equal footing with all incoming transactions combined.
#[derive(Clone)]
pub struct BlockProducerHandle {
    pub(super) mempool: Arc<Mutex<SharedMempool>>,
    pub(super) store: StoreClient,
    pub(super) cached_mempool_stats: Arc<RwLock<MempoolStats>>,
}

impl BlockProducerHandle {
    pub(super) fn new(mempool: SharedMempool, store: StoreClient) -> Self {
        Self {
            mempool: Arc::new(Mutex::new(mempool)),
            store,
            cached_mempool_stats: Arc::new(RwLock::new(MempoolStats::default())),
        }
    }

    /// Starts a background task that periodically updates the cached mempool statistics.
    ///
    /// This prevents the need to lock the mempool for each status request.
    pub(super) async fn spawn_stats_updater(&self) {
        let cached_mempool_stats = Arc::clone(&self.cached_mempool_stats);
        let mempool = self.mempool.lock().await.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CACHED_MEMPOOL_STATS_UPDATE_INTERVAL);

            loop {
                interval.tick().await;

                let (chain_tip, unbatched_transactions, proposed_batches, proven_batches) = {
                    let mempool = mempool.lock().await;
                    (
                        mempool.chain_tip(),
                        mempool.unbatched_transactions_count() as u64,
                        mempool.proposed_batches_count() as u64,
                        mempool.proven_batches_count() as u64,
                    )
                };

                let mut cache = cached_mempool_stats.write().await;
                *cache = MempoolStats {
                    chain_tip,
                    unbatched_transactions,
                    proposed_batches,
                    proven_batches,
                };
            }
        });
    }

    #[instrument(
        target = COMPONENT,
        name = "block_producer.server.submit_proven_tx",
        skip_all,
        err
    )]
    pub async fn submit_proven_tx(
        &self,
        request: proto::transaction::ProvenTransaction,
    ) -> Result<tonic::Response<proto::blockchain::BlockNumber>, Status> {
        debug!(target: COMPONENT, ?request);

        let tx = ProvenTransaction::read_from_bytes(&request.transaction)
            .map_err(MempoolSubmissionError::DeserializationFailed)?;

        let tx_id = tx.id();

        debug!(
            target: COMPONENT,
            tx_id = %tx_id.to_hex(),
            account_id = %tx.account_id().to_hex(),
            initial_state_commitment = %tx.account_update().initial_state_commitment(),
            final_state_commitment = %tx.account_update().final_state_commitment(),
            input_notes = %format_input_notes(tx.input_notes()),
            output_notes = %format_output_notes(tx.output_notes()),
            ref_block_commitment = %tx.ref_block_commitment(),
            "Deserialized transaction"
        );
        debug!(target: COMPONENT, proof = ?tx.proof());

        let inputs = self
            .store
            .get_tx_inputs(&tx)
            .await
            .map_err(MempoolSubmissionError::StoreConnectionFailed)?;

        // SAFETY: we assume that the rpc component has verified the transaction proof already.
        let tx = AuthenticatedTransaction::new_unchecked(Arc::new(tx), inputs)
            .map(Arc::new)
            .map_err(MempoolSubmissionError::StateConflict)?;

        self.mempool
            .lock()
            .await
            .lock()
            .await
            .add_transaction(tx)
            .map(Into::into)
            .map(tonic::Response::new)
            .map_err(Into::into)
    }

    #[instrument(
        target = COMPONENT,
        name = "block_producer.server.submit_proven_tx_batch",
        skip_all,
        err
    )]
    pub async fn submit_proven_tx_batch(
        &self,
        request: proto::transaction::TransactionBatch,
    ) -> Result<tonic::Response<proto::blockchain::BlockNumber>, Status> {
        let proposed = request
            .proposed_batch
            .expect("proposed batch existence is enforced by RPC component");
        let batch = ProposedBatch::read_from_bytes(&proposed)
            .map_err(MempoolSubmissionError::DeserializationFailed)?;

        let mut txs = Vec::with_capacity(batch.transactions().len());
        for tx in batch.transactions() {
            let inputs = self
                .store
                .get_tx_inputs(tx)
                .await
                .map_err(MempoolSubmissionError::StoreConnectionFailed)?;

            // SAFETY: We assume that the rpc component has verified the transaction proofs, as well
            // as the batch integrity itself.
            let tx = AuthenticatedTransaction::new_unchecked(Arc::clone(tx), inputs)
                .map(Arc::new)
                .map_err(MempoolSubmissionError::StateConflict)?;
            txs.push(tx);
        }

        self.mempool
            .lock()
            .await
            .lock()
            .await
            .add_user_batch(&txs)
            .map(Into::into)
            .map(tonic::Response::new)
            .map_err(Into::into)
    }

    pub async fn status(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<tonic::Response<proto::rpc::BlockProducerStatus>, Status> {
        let stats = *self.cached_mempool_stats.read().await;
        Ok(tonic::Response::new(proto::rpc::BlockProducerStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "connected".to_string(),
            chain_tip: stats.chain_tip.as_u32(),
            mempool_stats: Some(stats.into()),
        }))
    }

    pub(super) async fn subscribe(&self) -> ReceiverStream<MempoolEvent> {
        ReceiverStream::new(self.mempool.lock().await.lock().await.subscribe())
    }
}

// BLOCK PRODUCER RPC SERVER
// ================================================================================================

/// Serves the block producer's RPC [api](api_server::Api).
///
/// A thin gRPC adapter over [`BlockProducerHandle`] — all business logic lives on the handle.
pub(super) struct BlockProducerRpcServer {
    handle: BlockProducerHandle,
}

impl BlockProducerRpcServer {
    pub(super) fn new(handle: BlockProducerHandle) -> Self {
        Self { handle }
    }

    pub(super) async fn serve(
        self,
        listener: TcpListener,
        grpc_options: GrpcOptionsInternal,
    ) -> anyhow::Result<()> {
        self.handle.spawn_stats_updater().await;

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(block_producer_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        tonic::transport::Server::builder()
            .accept_http1(true)
            .timeout(grpc_options.request_timeout)
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .add_service(api_server::ApiServer::new(self))
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .context("failed to serve block producer API")
    }
}

#[tonic::async_trait]
impl api_server::Api for BlockProducerRpcServer {
    type MempoolSubscriptionStream = MempoolEventSubscription;

    async fn submit_proven_tx(
        &self,
        request: tonic::Request<proto::transaction::ProvenTransaction>,
    ) -> Result<tonic::Response<proto::blockchain::BlockNumber>, Status> {
        self.handle.submit_proven_tx(request.into_inner()).await
    }

    async fn submit_proven_tx_batch(
        &self,
        request: tonic::Request<proto::transaction::TransactionBatch>,
    ) -> Result<tonic::Response<proto::blockchain::BlockNumber>, Status> {
        self.handle.submit_proven_tx_batch(request.into_inner()).await
    }

    async fn status(
        &self,
        request: tonic::Request<()>,
    ) -> Result<tonic::Response<proto::rpc::BlockProducerStatus>, Status> {
        self.handle.status(request).await
    }

    async fn mempool_subscription(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<tonic::Response<Self::MempoolSubscriptionStream>, tonic::Status> {
        Ok(tonic::Response::new(MempoolEventSubscription {
            inner: self.handle.subscribe().await,
        }))
    }
}

// MEMPOOL SUBSCRIPTION
// ================================================================================================

pub(super) struct MempoolEventSubscription {
    inner: ReceiverStream<MempoolEvent>,
}

impl tokio_stream::Stream for MempoolEventSubscription {
    type Item = Result<proto::block_producer::MempoolEvent, tonic::Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner
            .poll_next_unpin(cx)
            .map(|x| x.map(proto::block_producer::MempoolEvent::from).map(Result::Ok))
    }
}

// MEMPOOL STATISTICS
// ================================================================================================

/// Mempool statistics that are updated periodically to avoid locking the mempool.
#[derive(Clone, Copy, Default)]
pub(super) struct MempoolStats {
    /// The mempool's current view of the chain tip height.
    chain_tip: BlockNumber,
    /// Number of transactions currently in the mempool waiting to be batched.
    unbatched_transactions: u64,
    /// Number of batches currently being proven.
    proposed_batches: u64,
    /// Number of proven batches waiting for block inclusion.
    proven_batches: u64,
}

impl From<MempoolStats> for proto::rpc::MempoolStats {
    fn from(stats: MempoolStats) -> Self {
        proto::rpc::MempoolStats {
            unbatched_transactions: stats.unbatched_transactions,
            proposed_batches: stats.proposed_batches,
            proven_batches: stats.proven_batches,
        }
    }
}
