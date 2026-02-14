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

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use miden_node_proto::domain::mempool::MempoolEvent;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::TransactionId;
use subscription::SubscriptionProvider;
use tokio::sync::{Mutex, MutexGuard, mpsc};
use tracing::{instrument, warn};

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{AddTransactionError, VerifyTxError};
use crate::mempool::budget::BudgetStatus;
use crate::mempool::nodes::{BlockNode, Node, NodeId, ProposedBatchNode, TransactionNode};
use crate::{
    COMPONENT,
    DEFAULT_MEMPOOL_TX_CAPACITY,
    SERVER_MEMPOOL_EXPIRATION_SLACK,
    SERVER_MEMPOOL_STATE_RETENTION,
};

mod budget;
pub use budget::{BatchBudget, BlockBudget};

mod nodes;
mod state;
mod subscription;

#[cfg(test)]
mod tests;

// MEMPOOL CONFIGURATION
// ================================================================================================

#[derive(Clone)]
pub struct SharedMempool(Arc<Mutex<Mempool>>);

#[derive(Debug, Clone)]
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

#[derive(Clone, Debug)]
pub struct Mempool {
    /// Contains the aggregated state of all transactions, batches and blocks currently inflight in
    /// the mempool. Combines with `nodes` to describe the mempool's state graph.
    state: state::InflightState,

    /// Contains all the transactions, batches and blocks currently in the mempool.
    nodes: nodes::Nodes,

    chain_tip: BlockNumber,

    config: MempoolConfig,
    subscription: subscription::SubscriptionProvider,
}

// We have to implement this manually since the subscription channel does not implement PartialEq.
impl PartialEq for Mempool {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state && self.nodes == other.nodes
    }
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
            state: state::InflightState::default(),
            nodes: nodes::Nodes::default(),
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
        if self.nodes.uncommitted_tx_count() >= self.config.tx_capacity.get() {
            return Err(AddTransactionError::CapacityExceeded);
        }

        self.authentication_staleness_check(tx.authentication_height())?;
        self.expiration_check(tx.expires_at())?;

        // The transaction should append to the existing mempool state. This means:
        //
        // - The current account commitment should match the tx's initial state.
        // - No duplicate nullifiers are created.
        // - No duplicate notes are created.
        // - All unauthenticated notes exist as output notes.
        let account_commitment = self
            .state
            .account_commitment(&tx.account_id())
            .or(tx.store_account_state())
            .unwrap_or_default();
        if tx.account_update().initial_state_commitment() != account_commitment {
            return Err(VerifyTxError::IncorrectAccountInitialCommitment {
                tx_initial_account_commitment: tx.account_update().initial_state_commitment(),
                current_account_commitment: account_commitment,
            }
            .into());
        }
        let double_spend = self.state.nullifiers_exist(tx.nullifiers());
        if !double_spend.is_empty() {
            return Err(VerifyTxError::InputNotesAlreadyConsumed(double_spend).into());
        }
        let duplicates = self.state.output_notes_exist(tx.output_note_commitments());
        if !duplicates.is_empty() {
            return Err(VerifyTxError::OutputNotesAlreadyExist(duplicates).into());
        }
        let missing = self.state.output_notes_missing(tx.unauthenticated_note_commitments());
        if !missing.is_empty() {
            return Err(VerifyTxError::UnauthenticatedNotesNotFound(missing).into());
        }

        // Insert the transaction node.
        self.subscription.transaction_added(&tx);
        let tx = TransactionNode::new(tx);
        self.state.insert(NodeId::Transaction(tx.id()), &tx);
        self.nodes.txs.insert(tx.id(), tx);

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
        // The selection algorithm is fairly neanderthal in nature.
        //
        // We iterate over all transaction nodes, each time selecting the first transaction which
        // has no parent nodes that are unselected transactions. This is fairly primitive, but
        // avoids the manual bookkeeping of which transactions are selectable.
        //
        // Note that selecting a transaction can unblock other transactions. This implementation
        // handles this by resetting the iteration whenever a transaction is selected.
        //
        // This is still reasonably performant given that we only retain unselected transactions as
        // transaction nodes i.e. selected transactions become batch nodes.
        //
        // The additional bookkeeping can be implemented once we have fee related strategies. KISS.

        let mut selected = SelectedBatch::builder();
        let mut budget = self.config.batch_budget;

        let mut candidates = self.nodes.txs.values();

        'next: while let Some(candidate) = candidates.next() {
            if selected.contains(&candidate.id()) {
                continue 'next;
            }

            // A transaction may be placed in a batch IFF all parents were already in a batch (or
            // are part of this one).
            for parent in self.state.parents(NodeId::Transaction(candidate.id()), candidate) {
                match parent {
                    // TODO(mirko): Once user batches are supported, they will also need to be
                    // checked here.
                    NodeId::Transaction(parent) if !selected.contains(&parent) => {
                        continue 'next;
                    },
                    NodeId::Transaction(_)
                    | NodeId::ProposedBatch(_)
                    | NodeId::ProvenBatch(_)
                    | NodeId::Block(_) => {},
                }
            }

            if budget.check_then_subtract(candidate.inner()) == BudgetStatus::Exceeded {
                break;
            }

            candidates = self.nodes.txs.values();
            selected.push(candidate.inner().clone());
        }

        if selected.is_empty() {
            return None;
        }
        let selected = selected.build();

        let batch = ProposedBatchNode::new(selected.clone());
        let batch_id = batch.batch_id();

        for tx in batch.transactions() {
            let node =
                self.nodes.txs.remove(&tx.id()).expect("selected transaction node must exist");
            self.state.remove(&node);
            tracing::info!(
                batch.id = %batch_id,
                transaction.id = %tx.id(),
                "Transaction selected for inclusion in batch"
            );
        }
        self.state.insert(NodeId::ProposedBatch(batch_id), &batch);
        self.nodes.proposed_batches.insert(batch_id, batch);

        // TODO(mirko): Selecting a batch can unblock user batches, which should be checked here.

        self.inject_telemetry();
        Some(selected)
    }

    /// Drops the proposed batch and all of its descendants.
    ///
    /// Transactions are re-queued.
    #[instrument(target = COMPONENT, name = "mempool.rollback_batch", skip_all)]
    pub fn rollback_batch(&mut self, batch: BatchId) {
        // Due to the distributed nature of the system, its possible that a proposed batch was
        // already proven, or already reverted. This guards against this eventuality.
        if !self.nodes.proposed_batches.contains_key(&batch) {
            return;
        }

        // TODO(mirko): This will be somewhat complicated by the introduction of user batches
        // since these don't have all inner txs present and therefore must at least partially
        // revert their own tx descendents.

        // Remove all descendents and reinsert their transactions. This is safe to do since
        // a batch's state impact is the aggregation of its transactions.
        let reverted = self.revert_subtree(NodeId::ProposedBatch(batch));

        for (_, node) in reverted {
            for tx in node.transactions() {
                let tx = TransactionNode::new(Arc::clone(tx));
                let tx_id = tx.id();
                self.state.insert(NodeId::Transaction(tx_id), &tx);
                self.nodes.txs.insert(tx_id, tx);
                tracing::info!(
                    batch.id = %batch,
                    transaction.id = %tx_id,
                    "Transaction requeued as part of batch rollback"
                );
            }
        }

        self.inject_telemetry();
    }

    /// Marks a batch as proven if it exists.
    #[instrument(target = COMPONENT, name = "mempool.commit_batch", skip_all)]
    pub fn commit_batch(&mut self, proof: Arc<ProvenBatch>) {
        // Due to the distributed nature of the system, its possible that a proposed batch was
        // already proven, or already reverted. This guards against this eventuality.
        let Some(proposed) = self.nodes.proposed_batches.remove(&proof.id()) else {
            return;
        };

        self.state.remove(&proposed);

        let proven = proposed.into_proven_batch_node(proof);
        self.state.insert(NodeId::ProvenBatch(proven.id()), &proven);
        self.nodes.proven_batches.insert(proven.id(), proven);

        self.inject_telemetry();
    }

    /// Adds a user-submitted proven batch to the mempool.
    ///
    /// This is used for batches that were proven externally and submitted directly,
    /// bypassing the internal proposed batch stage.
    ///
    /// # Returns
    ///
    /// Returns the current block height.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch has expired.
    #[instrument(target = COMPONENT, name = "mempool.add_proven_batch", skip_all)]
    pub fn add_proven_batch(
        &mut self,
        batch: Arc<ProvenBatch>,
    ) -> Result<BlockNumber, AddTransactionError> {
        // Check if batch has expired
        self.expiration_check(batch.batch_expiration_block_num())?;

        // Check if batch already exists
        if self.nodes.proven_batches.contains_key(&batch.id()) {
            // Batch already exists, return current chain tip
            return Ok(self.chain_tip);
        }

        // Try to find transactions in mempool by their IDs from batch headers
        let mut txs = Vec::new();
        for tx_header in batch.transactions().as_slice() {
            let tx_id = tx_header.id();
            if let Some(tx_node) = self.nodes.txs.get(&tx_id) {
                txs.push(Arc::clone(tx_node.inner()));
            }
        }

        // Create ProvenBatchNode
        // Note: If transactions are not found in mempool, we create the node with empty list.
        // This is acceptable per the proto documentation which states transactions may not be
        // in the mempool yet or at all.
        use crate::mempool::nodes::ProvenBatchNode;
        let proven_node = ProvenBatchNode { txs, inner: batch };

        let batch_id = proven_node.id();

        // Insert into state and nodes
        self.state.insert(NodeId::ProvenBatch(batch_id), &proven_node);
        self.nodes.proven_batches.insert(batch_id, proven_node);

        self.inject_telemetry();

        Ok(self.chain_tip)
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
        // The selection algorithm is fairly neanderthal in nature.
        //
        // We iterate over all proven batch nodes, each time selecting the first which has no
        // parent nodes that are unselected batches.
        //
        // Note that selecting a batch can unblock other batches. This implementation handles this
        // by resetting the iteration whenever a batch is selected.

        assert!(
            self.nodes.proposed_block.is_none(),
            "block {} is already in progress",
            self.nodes.proposed_block.as_ref().unwrap().0
        );

        let block_number = self.chain_tip.child();
        let mut selected = BlockNode::new(block_number);
        let mut budget = self.config.block_budget;
        let mut candidates = self.nodes.proven_batches.values();

        'next: while let Some(candidate) = candidates.next() {
            if selected.contains(candidate.id()) {
                continue 'next;
            }

            // A batch is selectable if all parents are already blocks, or if the batch is part of
            // the current block selection.
            for parent in self.state.parents(NodeId::ProvenBatch(candidate.id()), candidate) {
                match parent {
                    NodeId::Block(_) => {},
                    NodeId::ProvenBatch(parent) if selected.contains(parent) => {},
                    _ => continue 'next,
                }
            }

            if budget.check_then_subtract(candidate.inner()) == BudgetStatus::Exceeded {
                break;
            }

            // Reset iteration as this batch could have unblocked previous batches.
            candidates = self.nodes.proven_batches.values();
            selected.push(candidate.clone());
        }

        // Replace the batches with the block in state and nodes.
        for batch in selected.batches() {
            // SAFETY: Selected batches came from nodes, and are unique.
            let batch = self.nodes.proven_batches.remove(&batch.id()).unwrap();
            self.state.remove(&batch);
            tracing::info!(
                block.number = %block_number,
                batch.id = %batch.id(),
                "Batch selected for inclusion in block",
            );
        }

        let block_number = self.chain_tip.child();
        let batches = selected.batches().to_vec();

        self.state.insert(NodeId::Block(block_number), &selected);
        self.nodes.proposed_block = Some((block_number, selected));

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
        let block = self
            .nodes
            .proposed_block
            .take_if(|(proposed, _)| proposed == &to_commit.block_num())
            .expect("block must be in progress to commit");
        let tx_ids = block.1.transactions().map(|tx| tx.id()).collect();

        self.nodes.committed_blocks.push_back(block);
        self.chain_tip = self.chain_tip.child();
        self.subscription.block_committed(to_commit, tx_ids);

        if self.nodes.committed_blocks.len() > self.config.state_retention.get() {
            let (_number, node) = self.nodes.committed_blocks.pop_front().unwrap();
            self.state.remove(&node);
        }
        let reverted_tx_ids = self.revert_expired_nodes();
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
        if self
            .nodes
            .proposed_block
            .as_ref()
            .is_none_or(|(proposed, _)| proposed != &block)
        {
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
        let reverted = self.revert_subtree(NodeId::Block(block));
        let mut reverted_txs = HashSet::default();

        // Log reverted batches and transactions.
        for (id, node) in reverted {
            match id {
                NodeId::ProposedBatch(batch_id) | NodeId::ProvenBatch(batch_id) => {
                    tracing::info!(
                        block.number=%block,
                        batch.id=%batch_id,
                        "Reverted batch as part of block rollback"
                    );
                },
                NodeId::Transaction(_) | NodeId::Block(_) => {},
            }

            for tx in node.transactions() {
                reverted_txs.insert(tx.id());
                tracing::info!(
                    block.number=%block,
                    transaction.id=%tx.id(),
                    "Reverted transaction as part of block rollback"
                );
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
    ///
    /// # Errors
    ///
    /// Returns an error if the provided chain tip does not match the mempool's chain tip. This
    /// prevents desync between the caller's view of the world and the mempool's event stream.
    #[instrument(target = COMPONENT, name = "mempool.subscribe", skip_all)]
    pub fn subscribe(
        &mut self,
        chain_tip: BlockNumber,
    ) -> Result<mpsc::Receiver<MempoolEvent>, BlockNumber> {
        self.subscription.subscribe(chain_tip)
    }

    // STATS & INSPECTION
    // --------------------------------------------------------------------------------------------

    /// Returns the number of transactions currently waiting to be batched.
    pub fn unbatched_transactions_count(&self) -> usize {
        self.nodes.txs.len()
    }

    /// Returns the number of batches currently being proven.
    pub fn proposed_batches_count(&self) -> usize {
        self.nodes.proposed_batches.len()
    }

    /// Returns the number of proven batches waiting for block inclusion.
    pub fn proven_batches_count(&self) -> usize {
        self.nodes.proven_batches.len()
    }

    // INTERNAL HELPERS
    // --------------------------------------------------------------------------------------------

    /// Adds mempool stats to the current tracing span.
    ///
    /// Note that these are only visible in the OpenTelemetry context, as conventional tracing
    /// does not track fields added dynamically.
    fn inject_telemetry(&self) {
        let span = tracing::Span::current();

        self.nodes.inject_telemetry(&span);
        self.state.inject_telemetry(&span);
    }

    /// Reverts expired transactions and batches as per the current `chain_tip`.
    ///
    /// Returns the list of all transactions that were reverted.
    fn revert_expired_nodes(&mut self) -> HashSet<TransactionId> {
        let expired_txs = self.nodes.txs.iter().filter_map(|(id, node)| {
            (node.expires_at() <= self.chain_tip).then_some(NodeId::Transaction(*id))
        });
        let expired_proposed_batches =
            self.nodes.proposed_batches.iter().filter_map(|(id, node)| {
                (node.expires_at() <= self.chain_tip).then_some(NodeId::ProposedBatch(*id))
            });
        let expired_proven_batches = self.nodes.proven_batches.iter().filter_map(|(id, node)| {
            (node.expires_at() <= self.chain_tip).then_some(NodeId::ProvenBatch(*id))
        });

        let expired = expired_proven_batches
            .chain(expired_proposed_batches)
            .chain(expired_txs)
            .collect::<Vec<_>>();
        let mut reverted_txs = HashSet::default();
        for expired_id in expired {
            let reverted = self.revert_subtree(expired_id);
            for (id, node) in reverted {
                match id {
                    NodeId::ProposedBatch(batch_id) | NodeId::ProvenBatch(batch_id) => {
                        tracing::info!(
                            ancestor=?expired_id,
                            batch.id=%batch_id,
                            "Reverted batch due to expiration of ancestor"
                        );
                    },
                    NodeId::Transaction(_) => {},
                    NodeId::Block(block_number) => panic!(
                        "Found block {block_number} descendent while reverting expired nodes which shouldn't be possible since only one block is in progress"
                    ),
                }

                for tx in node.transactions() {
                    reverted_txs.insert(tx.id());
                    tracing::info!(
                        ancestor=?expired_id,
                        transaction.id=%tx.id(),
                        "Reverted transaction due to expiration of ancestor"
                    );
                }
            }
        }

        reverted_txs
    }

    /// Reverts the subtree with the given root and returns the reverted nodes. Does nothing if the
    /// root node does not exist to allow using this in cases where multiple overlapping calls to
    /// this are made.
    fn revert_subtree(&mut self, root: NodeId) -> HashMap<NodeId, Box<dyn Node>> {
        let root_exists = match root {
            NodeId::Transaction(id) => self.nodes.txs.contains_key(&id),
            NodeId::ProposedBatch(id) => self.nodes.proposed_batches.contains_key(&id),
            NodeId::ProvenBatch(id) => self.nodes.proven_batches.contains_key(&id),
            NodeId::Block(id) => {
                self.nodes.proposed_block.as_ref().is_some_and(|(number, _)| *number == id)
            },
        };
        if !root_exists {
            return HashMap::default();
        }

        let mut to_process = vec![root];
        let mut reverted = HashMap::default();

        while let Some(id) = to_process.pop() {
            if reverted.contains_key(&id) {
                continue;
            }

            // SAFETY: all IDs come from the state DAG and must therefore exist. The processed check
            // above also prevents removing a node twice.
            let node: Box<dyn Node> = match id {
                NodeId::Transaction(id) => {
                    self.nodes.txs.remove(&id).map(|x| Box::new(x) as Box<dyn Node>)
                },
                NodeId::ProposedBatch(id) => {
                    self.nodes.proposed_batches.remove(&id).map(|x| Box::new(x) as Box<dyn Node>)
                },
                NodeId::ProvenBatch(id) => {
                    self.nodes.proven_batches.remove(&id).map(|x| Box::new(x) as Box<dyn Node>)
                },
                NodeId::Block(id) => self
                    .nodes
                    .proposed_block
                    .take_if(|(number, _)| number == &id)
                    .map(|(_, x)| Box::new(x) as Box<dyn Node>),
            }
            .unwrap();

            to_process.extend(self.state.children(id, node.as_ref()));
            self.state.remove(node.as_ref());
            reverted.insert(id, node);
        }

        reverted
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
        let oldest = self.nodes.oldest_committed_block().unwrap_or_default();
        let limit = oldest.parent().unwrap_or_default();

        if authentication_height < limit {
            return Err(AddTransactionError::StaleInputs {
                input_block: authentication_height,
                stale_limit: limit,
            });
        }

        let latest_block =
            self.nodes.proposed_block.as_ref().map_or(self.chain_tip, |(number, _)| *number);
        assert!(
            authentication_height <= latest_block,
            "Authentication height {authentication_height} exceeded the latest known block {latest_block}"
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
