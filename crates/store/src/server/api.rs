use std::sync::Arc;

use miden_node_proto::generated as proto;
use miden_protocol::block::BlockNumber;
use tokio::sync::{Semaphore, watch};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::COMPONENT;
use crate::state::{BlockCache, ProofCache, State};

// STORE API
// ================================================================================================

/// Maximum number of concurrent block or proof subscriptions allowed per sender.
pub(super) const MAX_REPLICA_SUBSCRIPTIONS: usize = 10;

#[derive(Clone)]
pub struct StoreApi {
    pub(super) state: Arc<State>,
    /// FIFO cache of recent committed blocks for replica block subscriptions.
    pub(super) block_cache: BlockCache,
    /// Watch receiver that wakes whenever a new block is committed.
    pub(super) committed_tip_rx: watch::Receiver<BlockNumber>,
    /// FIFO cache of recent block proofs for replica proof subscriptions.
    pub(super) proof_cache: ProofCache,
    /// Watch receiver that wakes whenever the proven-in-sequence tip advances.
    pub(super) proven_tip_rx: watch::Receiver<BlockNumber>,
    /// Limits concurrent block subscriptions to [`MAX_REPLICA_SUBSCRIPTIONS`].
    pub(super) block_subscription_semaphore: Arc<Semaphore>,
    /// Limits concurrent proof subscriptions to [`MAX_REPLICA_SUBSCRIPTIONS`].
    pub(super) proof_subscription_semaphore: Arc<Semaphore>,
}

impl StoreApi {
    pub(super) fn new(state: Arc<State>) -> Self {
        let committed_tip_rx = state.subscribe_committed_tip();
        let proven_tip_rx = state.subscribe_proven_tip();
        let block_cache = state.block_cache.clone();
        let proof_cache = state.proof_cache.clone();
        Self {
            state,
            block_cache,
            committed_tip_rx,
            proof_cache,
            proven_tip_rx,
            block_subscription_semaphore: Arc::new(Semaphore::new(MAX_REPLICA_SUBSCRIPTIONS)),
            proof_subscription_semaphore: Arc::new(Semaphore::new(MAX_REPLICA_SUBSCRIPTIONS)),
        }
    }

    /// Shared implementation for all `get_block_header_by_number` endpoints.
    pub async fn get_block_header_by_number_inner(
        &self,
        request: Request<proto::rpc::BlockHeaderByNumberRequest>,
    ) -> Result<Response<proto::rpc::BlockHeaderByNumberResponse>, Status> {
        info!(target: COMPONENT, ?request);
        let request = request.into_inner();

        let block_num = request.block_num.map(BlockNumber::from);
        let (block_header, mmr_proof) = self
            .state
            .get_block_header(block_num, request.include_mmr_proof.unwrap_or(false))
            .await?;

        Ok(Response::new(proto::rpc::BlockHeaderByNumberResponse {
            block_header: block_header.map(Into::into),
            chain_length: mmr_proof.as_ref().map(|p| p.forest().num_leaves() as u32),
            mmr_path: mmr_proof.map(|p| Into::into(p.merkle_path())),
        }))
    }
}

// UTILITIES
// ================================================================================================

/// Formats an "Internal error" error
pub fn internal_error<E: core::fmt::Display>(err: E) -> Status {
    Status::internal(err.to_string())
}
