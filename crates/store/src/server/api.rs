use std::collections::BTreeSet;
use std::sync::Arc;

use miden_node_proto::decode::ConversionResultExt;
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated as proto;
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockInputs, BlockNumber};
use miden_protocol::note::Nullifier;
use tokio::sync::{Semaphore, watch};
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::errors::GetBlockInputsError;
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

    /// Retrieves block inputs from state based on the contents of the supplied ordered batches.
    pub(crate) async fn block_inputs_from_ordered_batches(
        &self,
        batches: &OrderedBatches,
    ) -> Result<BlockInputs, GetBlockInputsError> {
        // Construct fields required to retrieve block inputs.
        let mut account_ids = BTreeSet::new();
        let mut nullifiers = Vec::new();
        let mut unauthenticated_note_commitments = BTreeSet::new();
        let mut reference_blocks = BTreeSet::new();

        for batch in batches.as_slice() {
            account_ids.extend(batch.updated_accounts());
            nullifiers.extend(batch.created_nullifiers());
            reference_blocks.insert(batch.reference_block_num());

            for note in batch.input_notes().iter() {
                if let Some(header) = note.header() {
                    unauthenticated_note_commitments.insert(header.id().as_word());
                }
            }
        }

        // Retrieve block inputs from the store.
        self.state
            .get_block_inputs(
                account_ids.into_iter().collect(),
                nullifiers,
                unauthenticated_note_commitments,
                reference_blocks,
            )
            .await
    }
}

// UTILITIES
// ================================================================================================

/// Formats an "Internal error" error
pub fn internal_error<E: core::fmt::Display>(err: E) -> Status {
    Status::internal(err.to_string())
}

/// Formats an "Invalid argument" error
pub fn invalid_argument<E: core::fmt::Display>(err: E) -> Status {
    Status::invalid_argument(err.to_string())
}

/// Converts `ConversionError` to Status for nullifier validation
pub fn conversion_error_to_status(value: &ConversionError) -> Status {
    invalid_argument(value.as_report_context("Invalid nullifier format"))
}

#[instrument(
    level = "debug",
    target = COMPONENT,
    skip_all,
    fields(nullifiers = nullifiers.len()),
    err
)]
pub fn validate_nullifiers<E>(nullifiers: &[proto::primitives::Digest]) -> Result<Vec<Nullifier>, E>
where
    E: From<ConversionError> + std::fmt::Display,
{
    nullifiers
        .iter()
        .copied()
        .map(Nullifier::try_from)
        .collect::<Result<_, ConversionError>>()
        .context("nullifiers")
        .map_err(Into::into)
}

#[instrument(
    level = "debug",
    target = COMPONENT,
    skip_all,
    fields(notes = notes.len()),
    err
)]
pub fn validate_note_commitments(notes: &[proto::primitives::Digest]) -> Result<Vec<Word>, Status> {
    notes
        .iter()
        .map(Word::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_argument("Digest field is not in the modulus range"))
}

#[instrument(
    level = "debug",
    target = COMPONENT,
    skip_all,
    fields(block_numbers = block_numbers.len())
)]
pub fn read_block_numbers(block_numbers: &[u32]) -> BTreeSet<BlockNumber> {
    BTreeSet::from_iter(block_numbers.iter().map(|raw_number| BlockNumber::from(*raw_number)))
}
