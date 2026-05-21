use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
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
use tracing::{debug, error, info, instrument};
use url::Url;

use crate::batch_builder::BatchBuilder;
use crate::block_builder::BlockBuilder;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{BlockProducerError, MempoolSubmissionError, StoreError};
use crate::mempool::{BatchBudget, BlockBudget, Mempool, MempoolConfig, SharedMempool};
use crate::store::StoreClient;
use crate::validator::BlockProducerValidatorClient;
use crate::{CACHED_MEMPOOL_STATS_UPDATE_INTERVAL, COMPONENT, SERVER_NUM_BATCH_BUILDERS};

#[cfg(test)]
mod tests;

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
    mempool: Arc<Mutex<SharedMempool>>,
    store: StoreClient,
    cached_mempool_stats: Arc<RwLock<MempoolStats>>,
}

impl BlockProducerHandle {
    fn new(mempool: SharedMempool, store: StoreClient) -> Self {
        Self {
            mempool: Arc::new(Mutex::new(mempool)),
            store,
            cached_mempool_stats: Arc::new(RwLock::new(MempoolStats::default())),
        }
    }

    /// Starts a background task that periodically updates the cached mempool statistics.
    ///
    /// This prevents the need to lock the mempool for each status request.
    async fn spawn_stats_updater(&self) {
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

    async fn subscribe(&self) -> ReceiverStream<MempoolEvent> {
        ReceiverStream::new(self.mempool.lock().await.lock().await.subscribe())
    }
}

// EMBEDDED BLOCK PRODUCER
// ================================================================================================

/// Block producer variant that uses an in-process store instead of a remote gRPC store.
pub struct EmbeddedBlockProducer {
    /// The address of the block producer component.
    pub block_producer_address: SocketAddr,
    /// The in-process store state.
    pub state: Arc<miden_node_store::State>,
    /// The address of the validator component.
    pub validator_url: Url,
    /// The address of the batch prover component.
    pub batch_prover_url: Option<Url>,
    /// The interval at which to produce batches.
    pub batch_interval: Duration,
    /// The interval at which to produce blocks.
    pub block_interval: Duration,
    /// The maximum number of transactions per batch.
    pub max_txs_per_batch: usize,
    /// The maximum number of batches per block.
    pub max_batches_per_block: usize,
    /// Server-side gRPC options.
    pub grpc_options: GrpcOptionsInternal,
    /// The maximum number of inflight transactions allowed in the mempool at once.
    pub mempool_tx_capacity: NonZeroUsize,
}

impl EmbeddedBlockProducer {
    /// Initialises the block producer internals and returns an in-process [`BlockProducerHandle`]
    /// together with a future that runs the gRPC server, batch builder, and block builder.
    ///
    /// Use this when the caller needs to submit transactions directly to the mempool without a
    /// gRPC round-trip (e.g. the embedded sequencer's RPC).
    pub async fn start(
        self,
    ) -> anyhow::Result<(BlockProducerHandle, impl Future<Output = anyhow::Result<()>> + Send)>
    {
        info!(target: COMPONENT, endpoint=?self.block_producer_address, "Initializing embedded server");
        let store = StoreClient::new_local(self.state.clone());
        let validator = BlockProducerValidatorClient::new(self.validator_url.clone());

        let chain_tip = self.state.chain_tip(miden_node_store::Finality::Committed).await;

        let block_builder = BlockBuilder::new(store.clone(), validator, self.block_interval);
        let batch_builder = BatchBuilder::new(
            store.clone(),
            SERVER_NUM_BATCH_BUILDERS,
            self.batch_prover_url,
            self.batch_interval,
        );
        let mempool = Mempool::shared(
            chain_tip,
            MempoolConfig {
                batch_budget: BatchBudget {
                    transactions: self.max_txs_per_batch,
                    ..BatchBudget::default()
                },
                block_budget: BlockBudget { batches: self.max_batches_per_block },
                tx_capacity: self.mempool_tx_capacity,
                ..Default::default()
            },
        );

        let handle = BlockProducerHandle::new(mempool.clone(), store);

        let grpc_options = self.grpc_options;
        let block_producer_address = self.block_producer_address;

        let serve = {
            let handle = handle.clone();
            async move {
                let listener = TcpListener::bind(block_producer_address)
                    .await
                    .context("failed to bind to block producer address")?;

                info!(target: COMPONENT, "Embedded server initialized");

                let mut tasks = tokio::task::JoinSet::new();

                let rpc_id = tasks
                    .spawn(async move {
                        BlockProducerRpcServer::new(handle).serve(listener, grpc_options).await
                    })
                    .id();

                let batch_builder_id = tasks
                    .spawn({
                        let mempool = mempool.clone();
                        async {
                            batch_builder.run(mempool).await;
                            Ok(())
                        }
                    })
                    .id();

                let block_builder_id = tasks.spawn(async { block_builder.run(mempool).await }).id();

                let task_ids = HashMap::from([
                    (batch_builder_id, "batch-builder"),
                    (block_builder_id, "block-builder"),
                    (rpc_id, "rpc"),
                ]);

                let task_result = tasks.join_next_with_id().await.unwrap();

                let task_id = match &task_result {
                    Ok((id, _)) => *id,
                    Err(err) => err.id(),
                };
                let task = task_ids.get(&task_id).unwrap_or(&"unknown");

                task_result
                    .map_err(|source| BlockProducerError::JoinError { task, source })
                    .map(|(_, result)| match result {
                        Ok(_) => Err(BlockProducerError::UnexpectedTaskCompletion { task }),
                        Err(source) => Err(BlockProducerError::TaskError { task, source }),
                    })
                    .and_then(|x| x)?
            }
        };

        Ok((handle, serve))
    }

    /// Serves the block-producer RPC API, the batch-builder and the block-builder.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        let (_handle, serve) = self.start().await?;
        serve.await
    }
}

// BLOCK PRODUCER
// ================================================================================================

/// The block producer server.
///
/// Specifies how to connect to the store, batch prover, and block prover components.
/// The connection to the store is established at startup and retried with exponential backoff
/// until the store becomes available. Once the connection is established, the block producer
/// will start serving requests.
pub struct BlockProducer {
    /// The address of the block producer component.
    pub block_producer_address: SocketAddr,
    /// The address of the store component.
    pub store_url: Url,
    /// The address of the validator component.
    pub validator_url: Url,
    /// The address of the batch prover component.
    pub batch_prover_url: Option<Url>,
    /// The interval at which to produce batches.
    pub batch_interval: Duration,
    /// The interval at which to produce blocks.
    pub block_interval: Duration,
    /// The maximum number of transactions per batch.
    pub max_txs_per_batch: usize,
    /// The maximum number of batches per block.
    pub max_batches_per_block: usize,
    /// Server-side gRPC options.
    pub grpc_options: GrpcOptionsInternal,

    /// The maximum number of inflight transactions allowed in the mempool at once.
    pub mempool_tx_capacity: NonZeroUsize,
}

impl BlockProducer {
    /// Serves the block-producer RPC API, the batch-builder and the block-builder.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        info!(target: COMPONENT, endpoint=?self.block_producer_address, store=%self.store_url, "Initializing server");
        let store = StoreClient::new(self.store_url.clone());
        let validator = BlockProducerValidatorClient::new(self.validator_url.clone());

        // Retry fetching the chain tip from the store until it succeeds.
        let mut retries_counter = 0;
        let chain_tip = loop {
            match store.latest_header().await {
                Err(StoreError::GrpcClientError(err)) => {
                    // exponential backoff with base 500ms and max 30s
                    let backoff = Duration::from_millis(500)
                        .saturating_mul(1 << retries_counter)
                        .min(Duration::from_secs(30));

                    error!(
                        store = %self.store_url,
                        ?backoff,
                        %retries_counter,
                        %err,
                        "store connection failed while fetching chain tip, retrying"
                    );

                    retries_counter += 1;
                    tokio::time::sleep(backoff).await;
                },
                Ok(header) => break header.block_num(),
                Err(e) => {
                    error!(target: COMPONENT, %e, "failed to fetch chain tip from store");
                    return Err(e.into());
                },
            }
        };

        let listener = TcpListener::bind(self.block_producer_address)
            .await
            .context("failed to bind to block producer address")?;

        info!(target: COMPONENT, "Server initialized");

        let block_builder = BlockBuilder::new(store.clone(), validator, self.block_interval);
        let batch_builder = BatchBuilder::new(
            store.clone(),
            SERVER_NUM_BATCH_BUILDERS,
            self.batch_prover_url,
            self.batch_interval,
        );
        let mempool = Mempool::shared(
            chain_tip,
            MempoolConfig {
                batch_budget: BatchBudget {
                    transactions: self.max_txs_per_batch,
                    ..BatchBudget::default()
                },
                block_budget: BlockBudget { batches: self.max_batches_per_block },
                tx_capacity: self.mempool_tx_capacity,
                ..Default::default()
            },
        );

        let handle = BlockProducerHandle::new(mempool.clone(), store);

        // Spawn rpc server and batch and block provers.
        //
        // These communicate indirectly via a shared mempool.
        //
        // These should run forever, so we combine them into a joinset so that if
        // any complete or fail, we can shutdown the rest (somewhat) gracefully.
        let mut tasks = tokio::task::JoinSet::new();

        let rpc_id = tasks
            .spawn(async move {
                BlockProducerRpcServer::new(handle).serve(listener, self.grpc_options).await
            })
            .id();

        let batch_builder_id = tasks
            .spawn({
                let mempool = mempool.clone();
                async {
                    batch_builder.run(mempool).await;
                    Ok(())
                }
            })
            .id();
        let block_builder_id = tasks
            .spawn({
                let mempool = mempool.clone();
                async { block_builder.run(mempool).await }
            })
            .id();

        let task_ids = HashMap::from([
            (batch_builder_id, "batch-builder"),
            (block_builder_id, "block-builder"),
            (rpc_id, "rpc"),
        ]);

        // Wait for any task to end. They should run indefinitely, so this is an unexpected result.
        //
        // SAFETY: The JoinSet is definitely not empty.
        let task_result = tasks.join_next_with_id().await.unwrap();

        let task_id = match &task_result {
            Ok((id, _)) => *id,
            Err(err) => err.id(),
        };
        let task = task_ids.get(&task_id).unwrap_or(&"unknown");

        // We could abort the other tasks here, but not much point as we're probably crashing the
        // node.
        task_result
            .map_err(|source| BlockProducerError::JoinError { task, source })
            .map(|(_, result)| match result {
                Ok(_) => Err(BlockProducerError::UnexpectedTaskCompletion { task }),
                Err(source) => Err(BlockProducerError::TaskError { task, source }),
            })
            .and_then(|x| x)?
    }
}

// BLOCK PRODUCER RPC SERVER
// ================================================================================================

/// Serves the block producer's RPC [api](api_server::Api).
///
/// A thin gRPC adapter over [`BlockProducerHandle`] — all business logic lives on the handle.
struct BlockProducerRpcServer {
    handle: BlockProducerHandle,
}

impl BlockProducerRpcServer {
    fn new(handle: BlockProducerHandle) -> Self {
        Self { handle }
    }

    async fn serve(
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

struct MempoolEventSubscription {
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
struct MempoolStats {
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
