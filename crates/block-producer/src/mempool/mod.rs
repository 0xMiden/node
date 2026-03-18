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
//! infeasible, and both blocks and batches have constraints. This is also undersireable since if
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
//! - Reverting a node reverts all descendents as well.
#![allow(unused, reason = "refactor wip")]

use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;

use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_utils::ErrorReport;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use subscription::SubscriptionProvider;
use tokio::sync::{Mutex, MutexGuard, mpsc};
use tracing::{instrument, warn};

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{AddTransactionError, VerifyTxError};
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
pub use graph::StateConflict;
mod subscription;

#[cfg(test)]
mod tests;

// MEMPOOL CONFIGURATION
// ================================================================================================

#[derive(Clone)]
pub struct SharedMempool(Arc<Mutex<Mempool>>);

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
    #[instrument(target = COMPONENT, name = "mempool.lock", skip_all)]
    pub async fn lock(&self) -> MutexGuard<'_, Mempool> {
        self.0.lock().await
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
    pending_block: Option<(BlockNumber, Vec<Arc<ProvenBatch>>)>,
    /// The most recently committed blocks in chronological order.
    ///
    /// Limited to the state retention amount defined in the config. Once a pending block is
    /// committed it is appended here, and the oldest block's state is prunned.
    committed_blocks: VecDeque<Vec<Arc<ProvenBatch>>>,

    chain_tip: BlockNumber,

    config: MempoolConfig,
    subscription: subscription::SubscriptionProvider,
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
            chain_tip,
            subscription: SubscriptionProvider::new(chain_tip),
            transactions: graph::TransactionGraph::default(),
            batches: graph::BatchGraph::default(),
            pending_block: None,
            committed_blocks: VecDeque::default(),
        }
    }

    /// Returns the current chain tip height as seen by the mempool.
    ///
    /// This reflects the latest committed block that the block producer is aware of.
    pub fn chain_tip(&self) -> BlockNumber {
        self.chain_tip
    }

    // TRANSACTION & BATCH LIFECYCLE
    // --------------------------------------------------------------------------------------------

    /// Adds a transaction to the mempool.
    ///
    /// Sends a [`MempoolEvent::TransactionAdded`] event to subscribers.
    ///
    /// # Returns
    ///
    /// Returns the current block height.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction's initial conditions don't match the current state.
    #[instrument(target = COMPONENT, name = "mempool.add_transaction", skip_all, fields(tx=%tx.id()))]
    pub fn add_transaction(
        &mut self,
        tx: Arc<AuthenticatedTransaction>,
    ) -> Result<BlockNumber, AddTransactionError> {
        if self.transactions.len() >= self.config.tx_capacity.get() {
            return Err(AddTransactionError::CapacityExceeded);
        }

        self.authentication_staleness_check(tx.authentication_height())?;
        self.expiration_check(tx.expires_at())?;
        self.transactions.append(Arc::clone(&tx))?;
        self.subscription.transaction_added(&tx);
        self.inject_telemetry();

        Ok(self.chain_tip)
    }

    /// Returns a set of transactions for the next batch.
    ///
    /// Transactions are returned in a valid execution ordering.
    ///
    /// Returns `None` if no transactions are available.
    #[instrument(target = COMPONENT, name = "mempool.select_batch", skip_all)]
    pub fn select_batch(&mut self) -> Option<SelectedBatch> {
        let batch = self.transactions.select_batch(self.config.batch_budget)?;
        if let Err(err) = self.batches.append(&batch) {
            panic!("failed to append batch to dependency graph: {}", err.as_report());
        }
        self.inject_telemetry();
        Some(batch)
    }

    /// Drops the proposed batch and all of its descendants.
    ///
    /// Transactions are re-queued.
    #[instrument(target = COMPONENT, name = "mempool.rollback_batch", skip_all)]
    pub fn rollback_batch(&mut self, batch: BatchId) {
        let reverted_batches = self.batches.revert_batch_and_descendents(batch);
        for reverted in reverted_batches {
            self.transactions.requeue_batch_transactions(reverted);
        }
        self.inject_telemetry();
    }

    /// Marks a batch as proven if it exists.
    #[instrument(target = COMPONENT, name = "mempool.commit_batch", skip_all)]
    pub fn commit_batch(&mut self, proof: Arc<ProvenBatch>) {
        self.batches.submit_proof(proof);
        self.inject_telemetry();
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
    #[instrument(target = COMPONENT, name = "mempool.select_block", skip_all)]
    pub fn select_block(&mut self) -> (BlockNumber, Vec<Arc<ProvenBatch>>) {
        assert!(
            self.pending_block.is_none(),
            "block {} is already in progress",
            self.pending_block.as_ref().unwrap().0
        );

        let block_number = self.chain_tip.child();
        let batches = self.batches.select_block(self.config.block_budget);

        self.pending_block = Some((block_number, batches.clone()));
        self.inject_telemetry();
        (block_number, batches)
    }

    /// Notify the pool that the in flight block was successfully committed to the chain.
    ///
    /// The pool will mark the associated batches and transactions as committed, and prune stale
    /// committed data, and purge transactions that are now considered expired.
    ///
    /// Sends a [`MempoolEvent::BlockCommitted`] event to subscribers, as well as a
    /// [`MempoolEvent::TransactionsReverted`] for transactions that are now considered expired.
    ///
    /// # Returns
    ///
    /// Returns a set of transactions that were purged from the mempool because they can no longer
    /// be included in the chain (e.g., expired transactions and their descendants).
    ///
    /// # Panics
    ///
    /// Panics if there is no block in flight.
    #[instrument(target = COMPONENT, name = "mempool.commit_block", skip_all)]
    pub fn commit_block(&mut self, to_commit: BlockHeader) {
        let (_, batches) = self
            .pending_block
            .take_if(|(proposed, _)| proposed == &to_commit.block_num())
            .expect("block must be in progress to commit");
        let tx_ids = batches
            .iter()
            .flat_map(|batch| batch.transactions().as_slice().iter())
            .map(miden_protocol::transaction::TransactionHeader::id)
            .collect();

        self.chain_tip = self.chain_tip.child();
        self.subscription.block_committed(to_commit, tx_ids);

        self.committed_blocks.push_back(batches);
        self.prune_oldest_block();

        let reverted_tx_ids = self.revert_expired();
        self.subscription.txs_reverted(reverted_tx_ids);
        self.inject_telemetry();
    }

    /// Notify the pool that construction of the in flight block failed.
    ///
    /// The pool will purge the block and all of its contents from the pool.
    ///
    /// Sends a [`MempoolEvent::TransactionsReverted`] event to subscribers.
    ///
    /// # Returns
    ///
    /// Returns a set of transaction IDs that were reverted because they can no longer be
    /// included in in the chain (e.g., expired transactions and their descendants)
    ///
    /// # Panics
    ///
    /// Panics if there is no block in flight.
    #[instrument(target = COMPONENT, name = "mempool.rollback_block", skip_all)]
    pub fn rollback_block(&mut self, block: BlockNumber) {
        // Only revert if the given block is actually inflight.
        //
        // This guards against extreme circumstances where multiple block proofs may be inflight at
        // once. Due to the distributed nature of the node, one can imagine a scenario where
        // multiple provers get the same job for example.
        //
        // FIXME: We should consider a more robust check here to identify the block by a hash.
        //        If multiple jobs are possible, then so are multiple variants with the same block
        //        number.
        if self.pending_block.as_ref().is_none_or(|(num, _)| num != &block) {
            return;
        }

        // Remove all descendents _without_ reinserting the transactions.
        //
        // This is done to prevent a system bug from causing repeated failures if we keep retrying
        // the same transactions. Since we can't trivially identify the cause of the block
        // failure, we take the safe route and nuke all associated state.
        //
        // A more refined approach could be to tag the offending transactions and then evict them
        // once a certain failure threshold has been met.
        let mut reverted_txs = HashSet::default();
        let (_, batches) = self.pending_block.take().unwrap();
        for batch in batches {
            let reverted = self.batches.revert_batch_and_descendents(batch.id());

            for batch in reverted {
                for tx in batch.into_transactions() {
                    reverted_txs.extend(self.transactions.revert_tx_and_descendents(tx.id()));
                }
            }
        }

        self.subscription.txs_reverted(reverted_txs);
        self.inject_telemetry();
    }

    // EVENTS & SUBSCRIPTIONS
    // --------------------------------------------------------------------------------------------

    /// Creates a subscription to [`MempoolEvent`] which will be emitted in the order they occur.
    ///
    /// Only emits events which occurred after the current committed block.
    #[instrument(target = COMPONENT, name = "mempool.subscribe", skip_all)]
    pub fn subscribe(&mut self) -> mpsc::Receiver<MempoolEvent> {
        self.subscription.subscribe()
    }

    // STATS & INSPECTION
    // --------------------------------------------------------------------------------------------

    /// Returns the number of transactions currently waiting to be batched.
    pub fn unbatched_transactions_count(&self) -> usize {
        todo!();
    }

    /// Returns the number of batches currently being proven.
    pub fn proposed_batches_count(&self) -> usize {
        todo!();
    }

    /// Returns the number of proven batches waiting for block inclusion.
    pub fn proven_batches_count(&self) -> usize {
        todo!();
    }

    // INTERNAL HELPERS
    // --------------------------------------------------------------------------------------------

    /// Adds mempool stats to the current tracing span.
    ///
    /// Note that these are only visible in the OpenTelemetry context, as conventional tracing
    /// does not track fields added dynamically.
    fn inject_telemetry(&self) {
        let span = tracing::Span::current();

        todo!();
    }

    /// Prunes the oldest locally retained block if the number of blocks exceeds the configured
    /// limit.
    ///
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
        for batch in block.iter().map(|batch| batch.id()) {
            self.batches.prune(batch);
        }

        for tx in block
            .iter()
            .flat_map(|batch| batch.transactions().as_slice())
            .map(TransactionHeader::id)
        {
            self.transactions.prune(tx);
        }
    }

    /// Reverts all batches and transactions that have expired.
    ///
    /// Expired batch descendents are also reverted since these are now invalid.
    ///
    /// Transactions from batches are requeued. Expired transactions and their descendents are then
    /// reverted as well.
    fn revert_expired(&mut self) -> HashSet<TransactionId> {
        let batches = self.batches.revert_expired(self.chain_tip);
        for batch in batches {
            self.transactions.requeue_batch_transactions(batch);
        }
        self.transactions.revert_expired(self.chain_tip)
    }

    /// Rejects authentication height's which we cannot guarantee are correct from the locally
    /// retained state.
    ///
    /// In other words, this returns an error if the authentication height is more than one block
    /// older than the locally retained state. One block is allowed because this means block `N-1`
    /// was authenticated by the store, and we can check blocks `N..chain_tip`.
    ///
    /// # Panics
    ///
    /// This panics if the authentication height exceeds the latest locally known block. This
    /// includes any proposed block since the block is committed to the mempool and store
    /// concurrently (or at least can be).
    fn authentication_staleness_check(
        &self,
        authentication_height: BlockNumber,
    ) -> Result<(), AddTransactionError> {
        let limit = self
            .chain_tip
            .as_usize()
            .checked_sub(self.committed_blocks.len())
            .expect("amount of committed blocks cannot exceed the chain tip");
        let limit = BlockNumber::from(limit as u32).parent().unwrap_or_default();

        if authentication_height < limit {
            return Err(AddTransactionError::StaleInputs {
                input_block: authentication_height,
                stale_limit: limit,
            });
        }

        assert!(
            authentication_height <= self.chain_tip,
            "Authentication height {authentication_height} exceeded the chain tip {}",
            self.chain_tip
        );

        Ok(())
    }

    fn expiration_check(&self, expired_at: BlockNumber) -> Result<(), AddTransactionError> {
        let limit = self.chain_tip + self.config.expiration_slack;
        if expired_at <= limit {
            return Err(AddTransactionError::Expired { expired_at, limit });
        }

        Ok(())
    }
}
