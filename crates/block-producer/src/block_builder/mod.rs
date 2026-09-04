use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::Arc;

use anyhow::Context;
use miden_node_store::state::{BlockWriter, State};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{ErrorSpanExt, Span, debug, miden_instrument, miden_span_record};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::batch::{OrderedBatches, ProvenBatch};
use miden_protocol::block::{
    BlockInputs,
    BlockNumber,
    BlockSignatures,
    ProposedBlock,
    SignedBlock,
};
use miden_protocol::transaction::TransactionHeader;
use tokio::time::Duration;

use crate::errors::{BuildBlockError, StoreError};
use crate::mempool::SharedMempool;
use crate::validator::BlockProducerValidatorClient;
use crate::{COMPONENT, LOG_TARGET};

// BLOCK BUILDER
// =================================================================================================

pub struct BlockBuilder {
    /// The frequency at which blocks are produced.
    pub block_interval: Duration,

    /// Read-only store state, used to fetch block inputs.
    pub state: Arc<State>,

    /// The store's block-write capability, used for committing blocks.
    pub block_writer: BlockWriter,

    /// The validator RPC client for validating blocks.
    pub validator: BlockProducerValidatorClient,
}

impl BlockBuilder {
    /// Creates a new [`BlockBuilder`] with the given block-write capability and optional block
    /// prover URL.
    ///
    /// If the block prover URL is not set, the block builder will use the local block prover.
    pub fn new(
        state: Arc<State>,
        block_writer: BlockWriter,
        validator: BlockProducerValidatorClient,
        block_interval: Duration,
    ) -> Self {
        Self {
            block_interval,
            state,
            block_writer,
            validator,
        }
    }
    /// Starts the [`BlockBuilder`], infinitely producing blocks at the configured interval.
    ///
    /// Returns only if there was a fatal, unrecoverable error.
    ///
    /// Block production is sequential and consists of
    ///
    ///   1. Pulling the next set of batches from the mempool
    ///   2. Compiling these batches into the next block
    ///   3. Proving the block (this is simulated using random sleeps)
    ///   4. Committing the block to the store
    pub async fn run(
        mut self,
        mempool: SharedMempool,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(self.block_interval);
        // We set the interval's missed tick behaviour to burst. This means we'll catch up missed
        // blocks as fast as possible. In other words, we try our best to keep the desired block
        // interval on average. The other options would result in at least one skipped block.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);

        loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                _ = interval.tick() => {},
            }

            // Exit if a fatal error occurred.
            //
            // No need for error logging since this is handled inside the function.
            match self.build_block(&mempool).await {
                Err(err @ BuildBlockError::Desync { local_chain_tip, .. }) => {
                    return Err(err).with_context(|| {
                        format!("fatal error while building block {}", local_chain_tip.child())
                    });
                },
                Err(err @ BuildBlockError::MempoolPoisoned(_)) => {
                    return Err(err).context("fatal error while accessing mempool");
                },
                Err(_) | Ok(()) => {},
            }
        }
    }

    /// Run the block building stages and add open-telemetry trace information where applicable.
    ///
    /// A failure in any stage will result in that block being rolled back.
    ///
    /// ## Telemetry
    ///
    /// - Creates a new root span which means each block gets its own complete trace.
    /// - Important telemetry fields are added to the root span with the `block.xxx` prefix.
    /// - Each stage has its own child span and are free to add further field data.
    /// - A failed stage will emit an error event, and both its own span and the root span will be
    ///   marked as errors.
    #[miden_instrument(
        parent = None,
        target = COMPONENT,
        name = "block_builder.build_block",
    )]
    async fn build_block(&mut self, mempool: &SharedMempool) -> Result<(), BuildBlockError> {
        use futures::TryFutureExt;

        let selected = Self::select_block(mempool)?;
        let telemetry = selected.telemetry();
        miden_span_record!(
            block.number = telemetry.block_number,
            block.batch.count = telemetry.batches_count,
            block.batch.ids = telemetry.batch_ids,
            block.transaction.ids = telemetry.transaction_ids,
            block.transaction.count = telemetry.transactions_count
        );
        let block_num = selected.block_number;

        // The stages run inside one async block so that its borrows are sequential: the combinator
        // chain's shared borrows of `self` end at its `.await`, after which `commit_block` may take
        // `&mut self` (the block-write capability). The `?` exits only this block, so the error
        // handling below still sees failures from every stage.
        async {
            let block_commit = self
                .get_block_inputs(selected)
                .inspect_ok(|inputs| {
                    let telemetry = inputs.telemetry();
                    miden_span_record!(
                        block.updated_account.count = telemetry.updated_accounts_count,
                        block.erased_note_proof.count = telemetry.erased_note_proofs_count
                    );
                })
                .and_then(|inputs| self.propose_block(inputs))
                .inspect_ok(|proposed_block| {
                    let telemetry = proposed_block_telemetry(&proposed_block.proposed_block);
                    miden_span_record!(
                        block.nullifier.count = telemetry.nullifiers_count,
                        block.output_note.count = telemetry.output_notes_count,
                        block.batch.output_note.count = telemetry.batch_output_notes_count,
                        block.erased_note.count = telemetry.erased_notes_count
                    );
                })
                .and_then(|proposed_block| self.build_and_validate_block(proposed_block))
                .await?;

            self.commit_block(mempool, block_commit).await
        }
        // Handle errors by propagating the error to the root span and rolling back the block.
        .inspect_err(|err| Span::current().set_error(err))
        .or_else(|err| async {
            Self::rollback_block(mempool, block_num)?;
            Err(err)
        })
        .await
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_builder.select_block",
    )]
    fn select_block(mempool: &SharedMempool) -> Result<SelectedBlock, BuildBlockError> {
        Ok(mempool.lock().map_err(BuildBlockError::MempoolPoisoned)?.select_block())
    }

    /// Fetches block inputs from the store for the [`SelectedBlock`].
    ///
    /// For a given set of batches, we need to get the following block inputs from the store:
    ///
    /// - Note inclusion proofs for unauthenticated notes (not required to be complete due to the
    ///   possibility of note erasure)
    /// - A chain MMR with:
    ///   - All blocks referenced by batches
    ///   - All blocks referenced by note inclusion proofs
    /// - Account witnesses for all accounts updated in the block
    /// - Nullifier witnesses for all nullifiers created in the block
    ///   - Due to note erasure the set of nullifiers the block creates it not necessarily equal to
    ///     the union of all nullifiers created in proven batches. However, since we don't yet know
    ///     which nullifiers the block will actually create, we fetch witnesses for all nullifiers
    ///     created by batches. If we knew that a certain note will be erased, we would not have to
    ///     supply a nullifier witness for it.
    #[miden_instrument(
        target = COMPONENT,
        name = "block_builder.get_block_inputs",
        err,
    )]
    async fn get_block_inputs(
        &self,
        selected_block: SelectedBlock,
    ) -> Result<BlockBatchesAndInputs, BuildBlockError> {
        let SelectedBlock { block_number, batches } = selected_block;

        let batch_iter = batches.iter();

        let unauthenticated_notes_iter = batch_iter.clone().flat_map(|batch| {
            // Note: .cloned() shouldn't be necessary but not having it produces an odd lifetime
            // error in BlockProducer::serve. Not sure if there's a better fix. Error:
            // implementation of `FnOnce` is not general enough closure with signature
            // `fn(&InputNoteCommitment) -> miden_protocol::note::NoteId` must implement
            // `FnOnce<(&InputNoteCommitment,)>` ...but it actually implements
            // `FnOnce<(&InputNoteCommitment,)>`
            batch
                .input_notes()
                .iter()
                .cloned()
                .filter_map(|note| note.header().map(miden_protocol::note::NoteHeader::id))
        });
        let block_references_iter =
            batch_iter.clone().map(Deref::deref).map(ProvenBatch::reference_block_num);
        let account_ids_iter =
            batch_iter.clone().map(Deref::deref).flat_map(ProvenBatch::updated_accounts);
        let created_nullifiers_iter =
            batch_iter.map(Deref::deref).flat_map(ProvenBatch::created_nullifiers);

        let account_ids = account_ids_iter.collect::<Vec<_>>();
        let created_nullifiers = created_nullifiers_iter.collect::<Vec<_>>();
        let mut block_numbers: BTreeSet<_> = block_references_iter.collect();
        let note_ids = unauthenticated_notes_iter.collect();
        let view = self.state.view();
        let reference_block = *view.tip();

        // The reference block must be the chain tip. Its account and nullifier roots must match the
        // witnesses from this view.
        let note_inclusion_proofs = view
            .get_note_inclusion_proofs(reference_block, note_ids)
            .await
            .map_err(StoreError::GetNoteInclusionProofsFailed)
            .map_err(BuildBlockError::FetchBlockInputsFailed)?;
        block_numbers
            .extend(note_inclusion_proofs.values().map(|proof| proof.location().block_num()));
        let partial_blockchain = view
            .get_block_inclusion_proofs(reference_block, block_numbers)
            .await
            .map_err(StoreError::GetBlockInclusionProofsFailed)
            .map_err(BuildBlockError::FetchBlockInputsFailed)?;
        let reference_block_header = view
            .get_block_header(Some(reference_block), false)
            .await
            .map_err(StoreError::GetBlockHeaderFailed)
            .map_err(BuildBlockError::FetchBlockInputsFailed)?
            .0
            .expect("reference block header should exist");
        let state_witnesses = view.get_state_witnesses(&account_ids, &created_nullifiers);

        let inputs = BlockInputs::new(
            reference_block_header,
            partial_blockchain,
            state_witnesses.account_witnesses,
            state_witnesses.nullifier_witnesses,
            note_inclusion_proofs,
        );

        // Check that the latest committed block in the store matches our expectations.
        //
        // Desync can occur since the mempool and store state are updated separately. For example,
        // the store may commit a block while the block builder rolls back its local mempool view
        // after a late failure.
        let store_chain_tip = inputs.prev_block_header().block_num();
        if store_chain_tip.child() != block_number {
            return Err(BuildBlockError::Desync {
                local_chain_tip: block_number
                    .parent()
                    .expect("block being built always has a parent"),
                store_chain_tip,
            });
        }

        Ok(BlockBatchesAndInputs { batches, inputs })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_builder.propose_block",
        err,
    )]
    async fn propose_block(
        &self,
        batches_inputs: BlockBatchesAndInputs,
    ) -> Result<ProposedBlockAndInputs, BuildBlockError> {
        let BlockBatchesAndInputs { batches, inputs } = batches_inputs;
        let block_inputs = inputs.clone();
        let batches = batches.into_iter().map(Arc::unwrap_or_clone).collect();

        let proposed_block =
            ProposedBlock::new(inputs, batches).map_err(BuildBlockError::ProposeBlockFailed)?;

        Ok(ProposedBlockAndInputs { proposed_block, block_inputs })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_builder.validate_block",
        err,
    )]
    async fn build_and_validate_block(
        &self,
        proposal: ProposedBlockAndInputs,
    ) -> Result<BlockCommit, BuildBlockError> {
        let ProposedBlockAndInputs { proposed_block, block_inputs } = proposal;

        // Concurrently build the block and validate it via the validators.
        let build_result = spawn_blocking_in_current_span({
            let proposed_block = proposed_block.clone();
            move || proposed_block.into_header_and_body()
        });
        let responses = self
            .validator
            .sign_block(proposed_block.clone())
            .await
            .map_err(|err| BuildBlockError::ValidateBlockFailed(err.into()))?;
        let (header, body) = build_result
            .await
            .map_err(|err| BuildBlockError::other(format!("task join error: {err}")))?
            .map_err(BuildBlockError::ProposeBlockFailed)?;

        // Every validator and the block producer must derive the same block from the same proposed
        // block. Comparing the commitment each validator signed against the locally built one
        // isolates a block-hash mismatch from a key/algorithm problem in the signature check below.
        for response in &responses {
            if response.block_commitment != header.commitment() {
                return Err(BuildBlockError::BlockCommitmentMismatch {
                    validator: response.block_commitment,
                    sequencer: header.commitment(),
                });
            }
        }

        // Place each validator's signature at its position in the block's signature set. The
        // signature at position `i` must be produced by the key at index `i` of the validator set
        // committed to by the parent block's header.
        let parent_header = block_inputs.prev_block_header();
        let signatures = parent_header
            .validator_config()
            .keys()
            .iter()
            .enumerate()
            .map(|(position, key)| {
                responses
                    .iter()
                    .find(|response| &response.public_key == key)
                    .map(|response| response.signature.clone())
                    .ok_or(BuildBlockError::MissingValidatorSignature { position })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signatures = BlockSignatures::new(signatures)
            .map_err(|err| BuildBlockError::other(format!("invalid signature set: {err}")))?;

        // Verify the signatures against the built block to ensure that every validator has provided
        // a valid signature for the relevant block.
        signatures
            .verify_against(header.commitment(), parent_header.validator_config())
            .map_err(|_| BuildBlockError::InvalidSignature)?;

        let (ordered_batches, ..) = proposed_block.into_parts();

        // SAFETY: The header, body, and signatures are known to correspond to each other because
        // the header and body are derived from the proposed block and the signatures are verified
        // against the corresponding commitment.
        let signed_block = SignedBlock::new_unchecked(header, body, signatures);
        Ok(BlockCommit {
            ordered_batches,
            block_inputs,
            signed_block,
        })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_builder.commit_block",
        err,
    )]
    async fn commit_block(
        &mut self,
        mempool: &SharedMempool,
        block_commit: BlockCommit,
    ) -> Result<(), BuildBlockError> {
        let BlockCommit {
            ordered_batches,
            block_inputs,
            signed_block,
        } = block_commit;
        let header = signed_block.header().clone();
        let num_transactions = signed_block.body().transactions().as_slice().len();

        miden_span_record!(
            block.number = header.block_num(),
            block.commitment = header.commitment(),
            block.transaction.count = num_transactions
        );

        if num_transactions > 0 {
            debug!(
                target: LOG_TARGET,
                "Included transactions",
                block.transaction.count = num_transactions
            );
        }

        self.block_writer
            .apply_block_with_proving_inputs(ordered_batches, block_inputs, signed_block)
            .await
            .map_err(StoreError::ApplyBlockFailed)
            .map_err(BuildBlockError::StoreApplyBlockFailed)?;

        mempool.lock().map_err(BuildBlockError::MempoolPoisoned)?.commit_block(&header);

        Ok(())
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_builder.rollback_block",
    )]
    fn rollback_block(mempool: &SharedMempool, block: BlockNumber) -> Result<(), BuildBlockError> {
        mempool.lock().map_err(BuildBlockError::MempoolPoisoned)?.rollback_block(block);
        Ok(())
    }
}

/// A wrapper around batches selected for inlucion in a block, primarily used to be able to inject
/// telemetry in-between the selection and fetching the required [`BlockInputs`].
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedBlock {
    pub block_number: BlockNumber,
    pub batches: Vec<Arc<ProvenBatch>>,
}

struct SelectedBlockTelemetry {
    block_number: BlockNumber,
    batches_count: usize,
    batch_ids: Vec<miden_protocol::batch::BatchId>,
    transaction_ids: Vec<miden_protocol::transaction::TransactionId>,
    transactions_count: usize,
}

impl SelectedBlock {
    fn telemetry(&self) -> SelectedBlockTelemetry {
        // Accumulate all telemetry based on batches.
        let (batch_ids, tx_ids, tx_count) = self.batches.iter().fold(
            (Vec::new(), Vec::new(), 0),
            |(mut batch_ids, mut tx_ids, tx_count), batch| {
                let tx_count = tx_count + batch.transactions().as_slice().len();
                tx_ids.extend(batch.transactions().as_slice().iter().map(TransactionHeader::id));
                batch_ids.push(batch.id());
                (batch_ids, tx_ids, tx_count)
            },
        );
        SelectedBlockTelemetry {
            block_number: self.block_number,
            batches_count: self.batches.len(),
            batch_ids,
            transaction_ids: tx_ids,
            transactions_count: tx_count,
        }
    }
}

/// A wrapper around the inputs needed to build a [`ProposedBlock`], primarily used to be able to
/// inject telemetry in-between fetching block inputs and proposing the block.
struct BlockBatchesAndInputs {
    batches: Vec<Arc<ProvenBatch>>,
    inputs: BlockInputs,
}

/// A proposed block bundled with the exact inputs used to construct it.
struct ProposedBlockAndInputs {
    proposed_block: ProposedBlock,
    block_inputs: BlockInputs,
}

/// Data needed to commit a signed block and persist its proving inputs.
struct BlockCommit {
    ordered_batches: OrderedBatches,
    block_inputs: BlockInputs,
    signed_block: SignedBlock,
}

struct BlockInputsTelemetry {
    updated_accounts_count: usize,
    erased_note_proofs_count: usize,
}

impl BlockBatchesAndInputs {
    fn telemetry(&self) -> BlockInputsTelemetry {
        BlockInputsTelemetry {
            updated_accounts_count: self.inputs.account_witnesses().len(),
            erased_note_proofs_count: self.inputs.unauthenticated_note_proofs().len(),
        }
    }
}

#[expect(clippy::struct_field_names)]
struct ProposedBlockTelemetry {
    nullifiers_count: usize,
    output_notes_count: usize,
    batch_output_notes_count: usize,
    erased_notes_count: usize,
}

/// Extract the input and output note related telemetry. We do this here since this is the earliest
/// point we can observe it after note erasure was done.
fn proposed_block_telemetry(block: &ProposedBlock) -> ProposedBlockTelemetry {
    let num_block_created_notes: usize = block.output_note_batches().iter().map(Vec::len).sum();
    let num_batch_created_notes = block.batches().num_created_notes();

    let num_erased_notes = num_batch_created_notes
        .checked_sub(num_block_created_notes)
        .expect("all batches in the block should not create fewer notes than the block itself");

    ProposedBlockTelemetry {
        nullifiers_count: block.created_nullifiers().len(),
        output_notes_count: num_block_created_notes,
        batch_output_notes_count: num_batch_created_notes,
        erased_notes_count: num_erased_notes,
    }
}
