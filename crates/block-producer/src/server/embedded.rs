use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptionsInternal;
use tokio::net::TcpListener;
use tracing::info;
use url::Url;

use super::{BlockProducerHandle, BlockProducerRpcServer};
use crate::batch_builder::BatchBuilder;
use crate::block_builder::BlockBuilder;
use crate::errors::BlockProducerError;
use crate::mempool::{BatchBudget, BlockBudget, Mempool, MempoolConfig};
use crate::store::StoreClient;
use crate::validator::BlockProducerValidatorClient;
use crate::{COMPONENT, SERVER_NUM_BATCH_BUILDERS};

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
