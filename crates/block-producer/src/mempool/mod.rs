//! The [`Mempool`] is responsible for receiving transactions, and proposing transactions for
//! inclusion in batches, and proposing batches for inclusion in the next block.
//!
//! It performs these tasks by maintaining a dependency graph between all inflight transactions,
//! batches and blocks. A parent-child dependency edge between two nodes exists whenever the child
//! consumes a piece of state that the parent node created. To be more specific, node `A` is a
//! child of node `B`:
//!
//! - if `B` created an output note which is the input note of `A`, or
//! - if `B` updated an account to state `x'`, and `A` is updating this account from `x' -> x''`.
//!
//! Note that note dependency can only be tracked for unauthenticated input notes, because
//! authenticated notes have their IDs erased. This isn't a problem because authenticated notes are
//! guaranteed to be part of the committed state already by definition, and therefore we don't need
//! to concern ourselves with them. Double spending is also not possible because of nullifiers.
//!
//! Maintaining this dependency graph simplifies selecting transactions for new batches, and
//! selecting batches for new blocks. This follows from the blockchain requirement that each block
//! must build on the state of the previous block. This in turn implies that a child node can never
//! be committed in a block before all of its parents.
//!
//! The mempool also enforces that the graph contains no cycles i.e. that the dependency graph
//! is always a directed acyclic graph (DAG). While technically not illegal from a protocol
//! perspective, allowing cycles between nodes would require that all nodes within the cycle be
//! committed within the same block.
//!
//! While this is technically possible, the bookkeeping and implementation to allow this are
//! infeasible, and both blocks and batches have constraints. This is also undesirable since if
//! one component of such a cycle fails or expires, then all others would likewise need to be
//! reverted.
//!
//! The DAG nature of the graph is maintained by:
//!
//! - Ensuring incoming transactions are only ever appended to the current graph. This in turn
//!   implies that the transaction's state transition must build on top of the current mempool
//!   state.
//! - Parent/child edges between nodes in the graph are formed via state dependency.
//! - Transactions are proposed for batch inclusion only once _all_ its ancestors have already been
//!   included in a batch (or are part of the currently proposed batch).
//! - Similarly, batches are proposed for block inclusion once _all_ ancestors have been included in
//!   a block (or are part of the currently proposed block).
//! - Reverting a node reverts all descendants as well.
//!
//! The mempool maintains two DAGs: one for authenticated transactions awaiting batching and one for
//! batches awaiting inclusion in a block. As batches are selected, their constituent transactions
//! are marked in the transaction graph while the batch itself is appended to the batch graph. When
//! a block is proposed, the selected batches are staged in `pending_block` until the block is
//! either committed or rolled back.
//!
//! Recently committed batches are retained in `committed_blocks` according to the configured
//! `state_retention`, giving the mempool enough local history to validate newly authenticated
//! transactions even if the store and block producer momentarily disagree on the chain tip.
use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, LockResult, Mutex, MutexGuard};

use miden_node_utils::ErrorReport;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use thiserror::Error;

use crate::block_builder::SelectedBlock;
use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{MempoolSubmissionError, StateConflict};
use crate::mempool::budget::BudgetStatus;
use crate::{
    COMPONENT,
    DEFAULT_MEMPOOL_TX_CAPACITY,
    SERVER_MEMPOOL_EXPIRATION_SLACK,
    SERVER_MEMPOOL_STATE_RETENTION,
};

mod budget;
pub use budget::{BatchBudget, BlockBudget};

mod graph;

#[cfg(test)]
mod tests;

// MEMPOOL CONFIGURATION
// ================================================================================================

#[derive(Clone, Debug)]
pub struct SharedMempool(Arc<Mutex<Mempool>>);

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("shared mempool lock is poisoned")]
pub struct MempoolPoisonError;

#[derive(Debug, Clone, PartialEq)]
pub struct MempoolConfig {
    /// The constraints each proposed block must adhere to.
    pub block_budget: BlockBudget,

    /// The constraints each proposed batch must adhere to.
    pub batch_budget: BatchBudget,

    /// How close to the chain tip the mempool will allow submitted transactions and batches to
    /// expire.
    ///
    /// Submitted data which expires within this number of blocks to the chain tip will be
    /// rejected. This prevents accepting data which will likely expire before it can be
    /// included in a block.
    pub expiration_slack: u32,

    /// The number of recently committed blocks retained by the mempool.
    ///
    /// This retained state provides an overlap with the committed chain state in the store which
    /// mitigates race conditions for transaction and batch authentication.
    ///
    /// Authentication is done against the store state _before_ arriving at the mempool, and there
    /// is therefore opportunity for the chain state to have changed between authentication and the
    /// mempool handling the authenticated data. Retaining the recent blocks locally therefore
    /// guarantees that the mempool can verify the data against the additional changes so long as
    /// the data was authenticated against one of the retained blocks.
    ///
    /// Practically, retaining `state_retention` blocks lets the mempool authenticate any
    /// submission whose claimed height lies within `[chain_tip - state_retention + 1,
    /// chain_tip]`. Inputs authenticated before this window are rejected as stale to prevent
    /// gaps between the store and the locally retained history.
    pub state_retention: NonZeroUsize,

    /// The maximum number of uncommitted transactions allowed in the mempool at once.
    ///
    /// The mempool will reject transactions once it is at capacity.
    ///
    /// Transactions in batches and uncommitted blocks _do count_ towards this.
    pub tx_capacity: NonZeroUsize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            block_budget: BlockBudget::default(),
            batch_budget: BatchBudget::default(),
            expiration_slack: SERVER_MEMPOOL_EXPIRATION_SLACK,
            state_retention: SERVER_MEMPOOL_STATE_RETENTION,
            tx_capacity: DEFAULT_MEMPOOL_TX_CAPACITY,
        }
    }
}

// SHARED MEMPOOL
// ================================================================================================

impl SharedMempool {
    /// Acquires a lock on the underlying [`Mempool`].
    ///
    /// Callers should minimise the amount of work performed while holding the lock to reduce
    /// contention with other subsystems that need to access the pool.
    #[miden_node_utils::tracing::miden_instrument(target = COMPONENT, name = "mempool.lock", skip_all, err)]
    pub fn lock(&self) -> Result<MutexGuard<'_, Mempool>, MempoolPoisonError> {
        let result: LockResult<MutexGuard<'_, Mempool>> = self.0.lock();
        result.map_err(|_| MempoolPoisonError)
    }
}

// MEMPOOL
// ================================================================================================

#[derive(Clone, Debug, PartialEq)]
pub struct Mempool {
    /// Tracks the dependency graph for transactions awaiting batching.
    transactions: graph::TransactionGraph,
    /// Tracks the dependency graph for batches awaiting inclusion in a block.
    batches: graph::BatchGraph,
    /// The block currently being built, if any.
    pending_block: Option<SelectedBlock>,
    /// The most recently committed blocks in chronological order.
    ///
    /// Limited to the state retention amount defined in the config. Once a pending block is
    /// committed it is appended here, and the oldest block's state is pruned.
    committed_blocks: VecDeque<SelectedBlock>,

    committed_chain_tip: BlockNumber,

    config: MempoolConfig,
}

struct MempoolTelemetry {
    uncommitted_transactions: usize,
    unbatched_transactions: usize,
    proposed_batches: usize,
    proven_batches: usize,
    accounts: usize,
    nullifiers: usize,
    output_notes: usize,
}

impl Mempool {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`SharedMempool`] with the provided configuration.
    pub fn shared(chain_tip: BlockNumber, config: MempoolConfig) -> SharedMempool {
        SharedMempool(Arc::new(Mutex::new(Self::new(chain_tip, config))))
    }

    fn new(chain_tip: BlockNumber, config: MempoolConfig) -> Mempool {
        Self {
            config,
            committed_chain_tip: chain_tip,
            transactions: graph::TransactionGraph::default(),
            batches: graph::BatchGraph::default(),
            pending_block: None,
            committed_blocks: VecDeque::default(),
        }
    }

    /// Returns the current chain tip height as seen by the mempool.
    ///
    /// This includes the block currently being built, if any.
    pub fn chain_tip(&self) -> BlockNumber {
        self.pending_block
            .as_ref()
            .map_or(self.committed_chain_tip, |pending| pending.block_number)
    }

    // TRANSACTION & BATCH LIFECYCLE
    // --------------------------------------------------------------------------------------------

    /// Adds a transaction to the mempool.
    ///
    /// # Returns
    ///
    /// Returns the current block height.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction would exceed the mempool capacity or if its initial
    /// conditions don't match the current state.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Not impactful, and we may want ownership in the future"
    )]
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.add_transaction",
        skip_all
    )]
    pub fn add_transaction(
        &mut self,
        tx: Arc<AuthenticatedTransaction>,
    ) -> Result<BlockNumber, MempoolSubmissionError> {
        if self.unbatched_transactions_count() >= self.config.tx_capacity.get() {
            return Err(MempoolSubmissionError::CapacityExceeded);
        }

        self.authentication_staleness_check(tx.authentication_height())?;
        self.expiration_check(tx.expires_at())?;

        // Insert the transaction node.
        self.transactions
            .append(Arc::clone(&tx))
            .map_err(MempoolSubmissionError::StateConflict)?;
        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            transaction.id = %tx.id(),
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );

        Ok(self.committed_chain_tip)
    }

    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.add_user_batch",
        skip_all
    )]
    pub fn add_user_batch(
        &mut self,
        txs: &[Arc<AuthenticatedTransaction>],
    ) -> Result<BlockNumber, MempoolSubmissionError> {
        assert!(!txs.is_empty(), "Cannot have a batch with no transactions");

        if self.unbatched_transactions_count() + txs.len() > self.config.tx_capacity.get() {
            return Err(MempoolSubmissionError::CapacityExceeded);
        }

        // Ensure the batch doesn't exceed the mempool budget for batches.
        let mut budget = self.config.batch_budget;
        for tx in txs {
            if budget.check_then_subtract(tx) == BudgetStatus::Exceeded {
                // TODO: better error plox.
                return Err(MempoolSubmissionError::CapacityExceeded);
            }
        }

        for tx in txs {
            self.authentication_staleness_check(tx.authentication_height())?;
            self.expiration_check(tx.expires_at())?;
        }

        self.transactions
            .append_user_batch(txs)
            .map_err(MempoolSubmissionError::StateConflict)?;

        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );

        Ok(self.committed_chain_tip)
    }

    /// Returns a set of transactions for the next batch.
    ///
    /// Transactions are returned in a valid execution ordering.
    ///
    /// Returns `None` if no transactions are available.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.select_batch",
        skip_all
    )]
    pub fn select_batch(&mut self) -> Option<SelectedBatch> {
        let batch = self.transactions.select_batch(self.config.batch_budget)?;
        if let Err(err) = self.batches.append(batch.clone()) {
            panic!("failed to append batch to dependency graph: {}", err.as_report());
        }
        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );
        Some(batch)
    }

    /// Drops the proposed batch and all of its descendants.
    ///
    /// The transactions are re-queued for inclusion in a batch. Additionally, the batch's
    /// transactions have their failure count incremented, reverting them if they now exceed the
    /// failure limit.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.rollback_batch",
        skip_all
    )]
    pub fn rollback_batch(&mut self, batch: BatchId) {
        // Guards against bugs in the proof scheduler where a retry results in multiple results
        // coming back for the same batch. If the batch previously succeeded, then yanking it would
        // corrupt the mempool since the batch might be in a block.
        //
        // Either way, we simply ignore rollbacks of batches that have already succeeded as a
        // precaution.
        if self.batches.is_proven(&batch) {
            return;
        }

        let reverted_batches = self.batches.revert_batch_and_descendants(batch);
        for reverted in &reverted_batches {
            self.transactions.requeue_transactions(reverted);
        }

        // Find rolled back batch to mark the txs as failed.
        //
        // Note that it's possible it doesn't exist, since this batch could have already been
        // reverted as part of a separate rollback.
        //
        // This could occur if this batch is the descendent of a separate batch or block rollback.
        // The batch and transaction graphs already ignore unknown reversions, alternatively we
        // could check this precondition above.
        if let Some(batch) = reverted_batches.iter().find(|reverted| reverted.id() == batch) {
            let failed_txs = batch.transactions().iter().map(|tx| tx.id());
            self.transactions.increment_failure_count(failed_txs);
        }

        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );
    }

    /// Marks a batch as proven if it exists.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.commit_batch",
        skip_all
    )]
    pub fn commit_batch(&mut self, proof: Arc<ProvenBatch>) {
        self.batches.submit_proof(proof);
        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );
    }

    /// Select batches for the next block.
    ///
    /// Note that the set of batches
    /// - may be empty if none are available, and
    /// - may contain dependencies and therefore the order must be maintained
    ///
    /// # Panics
    ///
    /// Panics if there is already a block in flight.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.select_block",
        skip_all
    )]
    pub fn select_block(&mut self) -> SelectedBlock {
        assert!(
            self.pending_block.is_none(),
            "block {} is already in progress",
            self.pending_block.as_ref().unwrap().block_number
        );

        let block_number = self.chain_tip().child();
        let batches = self.batches.select_block(self.config.block_budget);
        let block = SelectedBlock { block_number, batches };
        self.pending_block = Some(block.clone());
        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );
        block
    }

    /// Notify the pool that the in flight block was successfully committed to the chain.
    ///
    /// The pool will mark the associated batches and transactions as committed, and prune stale
    /// committed data, and purge transactions that are now considered expired.
    ///
    /// On success the internal state is updated in place: the chain tip advances, expired data is
    /// pruned, and expired transactions are reverted.
    ///
    /// # Panics
    ///
    /// Panics if there is no matching block in flight.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.commit_block",
        skip_all
    )]
    pub fn commit_block(&mut self, block_header: &BlockHeader) {
        assert_eq!(self.committed_chain_tip.child(), block_header.block_num());
        let block = self
            .pending_block
            .take_if(|pending| pending.block_number == block_header.block_num())
            .expect("block must be in progress to commit");

        self.committed_chain_tip = self.committed_chain_tip.child();

        self.committed_blocks.push_back(block);
        self.prune_oldest_block();

        self.revert_expired();
        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );
    }

    /// Notify the pool that construction of the in flight block failed.
    ///
    /// The block's batches are reverted and transactions are requeued for batch selection.
    /// Additionally, the transactions from this block have their failure count incremented,
    /// potentially reverting them if they exceed the failure limit.
    ///
    /// # Panics
    ///
    /// Panics if there is no matching block in flight.
    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "mempool.rollback_block",
        skip_all
    )]
    pub fn rollback_block(&mut self, block: BlockNumber) {
        // FIXME: We should consider a more robust check here to identify the block by a hash.
        //        If multiple jobs are possible, then so are multiple variants with the same
        //        block number.
        let block = self
            .pending_block
            .take_if(|pending| pending.block_number == block)
            .expect("pending block must match block to rollback");

        // Revert the batches, and requeue the transactions for batch selection.
        //
        // Transactions which have failed excessively are also reverted.
        for batch in &block.batches {
            let reverted = self.batches.revert_batch_and_descendants(batch.id());

            for batch in reverted {
                self.transactions.requeue_transactions(&batch);
            }
        }
        let failed_txs = block
            .batches
            .iter()
            .flat_map(|batch| batch.transactions().as_slice().iter().map(TransactionHeader::id));
        self.transactions.increment_failure_count(failed_txs);
        let telemetry = self.telemetry();
        miden_node_utils::tracing::miden_span_record!(
            mempool.transactions.uncommitted = telemetry.uncommitted_transactions,
            mempool.transactions.unbatched = telemetry.unbatched_transactions,
            mempool.batches.proposed = telemetry.proposed_batches,
            mempool.batches.proven = telemetry.proven_batches,
            mempool.accounts = telemetry.accounts,
            mempool.nullifiers = telemetry.nullifiers,
            mempool.output_notes = telemetry.output_notes,
        );
    }

    // STATS & INSPECTION
    // --------------------------------------------------------------------------------------------

    /// Returns the number of transactions currently waiting to be batched.
    pub fn unbatched_transactions_count(&self) -> usize {
        self.transactions.unselected_count()
    }

    /// Returns the number of batches currently being proven.
    pub fn proposed_batches_count(&self) -> usize {
        self.batches.proposed_count()
    }

    /// Returns the number of proven batches waiting for block inclusion.
    pub fn proven_batches_count(&self) -> usize {
        self.batches.proven_count()
    }

    // INTERNAL HELPERS
    // --------------------------------------------------------------------------------------------

    fn telemetry(&self) -> MempoolTelemetry {
        let committed_txs = self
            .committed_blocks
            .iter()
            .flat_map(|block| block.batches.iter())
            .map(|batch| batch.transactions().as_slice().len())
            .sum::<usize>();
        MempoolTelemetry {
            uncommitted_transactions: self.transactions.count() - committed_txs,
            unbatched_transactions: self.unbatched_transactions_count(),
            proposed_batches: self.proposed_batches_count(),
            proven_batches: self.proven_batches_count(),
            accounts: self.transactions.accounts_count(),
            nullifiers: self.transactions.nullifier_count(),
            output_notes: self.transactions.output_note_count(),
        }
    }

    /// This includes pruning the block's batches and transactions from their graphs.
    fn prune_oldest_block(&mut self) {
        if self.committed_blocks.len() <= self.config.state_retention.get() {
            return;
        }
        let block = self.committed_blocks.pop_front().unwrap();

        // We perform pruning in chronological order, from oldest to youngest.
        //
        // Pruning a node requires that the node has no parents, and using chronological
        // order gives us this property. This works because a batch can only be included in
        // a block once _all_ its parents have been included. So if we follow the same order,
        // it means that a batch's parents would already have been pruned.
        //
        // The same logic follows for transactions.
        for batch in block.batches.iter().map(|batch| batch.id()) {
            let batch = self.batches.prune(batch);
            self.transactions.prune(&batch);
        }
    }

    /// Reverts all batches and transactions that have expired.
    ///
    /// Expired batch descendants are also reverted since these are now invalid.
    ///
    /// Transactions from batches are requeued. Expired transactions and their descendants are then
    /// reverted as well.
    fn revert_expired(&mut self) -> HashSet<TransactionId> {
        let batches = self.batches.revert_expired(self.chain_tip());
        for batch in batches {
            self.transactions.requeue_transactions(&batch);
        }
        self.transactions.revert_expired(self.chain_tip())
    }

    /// Rejects authentication heights that fall outside the overlap guaranteed by the locally
    /// retained state.
    ///
    /// If our oldest local block is at `N`, then we allow `N-1` and newer since this means we're
    /// covering the full blockchain.
    ///
    /// # Panics
    ///
    /// This panics if the authentication height exceeds the latest locally known block. This
    /// includes any proposed block since the block is committed to the mempool and store
    /// concurrently (or at least can be).
    fn authentication_staleness_check(
        &self,
        authentication_height: BlockNumber,
    ) -> Result<(), MempoolSubmissionError> {
        let limit = self
            .committed_blocks
            .front()
            .map_or(self.chain_tip(), |block| block.block_number)
            .parent()
            .unwrap_or_default();

        if authentication_height < limit {
            return Err(MempoolSubmissionError::StaleInputs {
                input_block: authentication_height,
                stale_limit: limit,
            });
        }

        assert!(
            authentication_height <= self.chain_tip(),
            "Authentication height {authentication_height} exceeded the chain tip {}",
            self.chain_tip()
        );

        Ok(())
    }

    fn expiration_check(&self, expired_at: BlockNumber) -> Result<(), MempoolSubmissionError> {
        let limit = self.chain_tip() + self.config.expiration_slack;
        if expired_at <= limit {
            return Err(MempoolSubmissionError::Expired { expired_at, limit });
        }

        Ok(())
    }
}
