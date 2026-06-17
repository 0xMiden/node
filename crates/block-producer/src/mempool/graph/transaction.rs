use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::BatchId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::StateConflict;
use crate::mempool::BatchBudget;
use crate::mempool::budget::BudgetStatus;
use crate::mempool::graph::dag::Graph;
use crate::mempool::graph::node::GraphNode;

// TRANSACTION GRAPH NODE
// ================================================================================================

impl GraphNode for Arc<AuthenticatedTransaction> {
    type Id = TransactionId;

    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.as_ref().nullifiers())
    }

    fn output_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.output_note_ids())
    }

    fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.unauthenticated_note_ids())
    }

    fn account_updates(
        &self,
    ) -> Box<dyn Iterator<Item = (AccountId, Word, Word, Option<Word>)> + '_> {
        let update = self.account_update();
        Box::new(std::iter::once((
            update.account_id(),
            update.initial_state_commitment(),
            update.final_state_commitment(),
            self.store_account_state(),
        )))
    }

    fn id(&self) -> Self::Id {
        self.as_ref().id()
    }

    fn expires_at(&self) -> BlockNumber {
        self.as_ref().expires_at()
    }
}

// TRANSACTION GRAPH
// ================================================================================================

/// Tracks all [`AuthenticatedTransaction`]s that are waiting to be included in a batch.
///
/// Each transaction is a node in the underlying [`Graph`]. A directed edge from transaction `P`
/// to transaction `C` exists when `C` depends on state produced by `P` — for example, `C`
/// consumes an output note created by `P`, or `C` updates an account from the state that `P`
/// left it in.
///
/// The graph is maintained as a DAG: transactions are only inserted once all their parent
/// dependencies are already present, and reverting a transaction also reverts all its
/// descendants.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TransactionGraph {
    inner: Graph<Arc<AuthenticatedTransaction>>,
    /// The number of failures a transaction has participated in.
    ///
    /// These are batch or block proving errors in which the transaction was a part of. This is
    /// used to identify potentially buggy transactions that should be evicted.
    failures: HashMap<TransactionId, u32>,

    /// Bijective mapping of user batches and their transactions.
    user_batches: BatchTxMap,
}

impl TransactionGraph {
    /// Transactions are evicted after failing this number of times.
    pub const FAILURE_LIMIT: u32 = 3;

    pub fn append(&mut self, tx: Arc<AuthenticatedTransaction>) -> Result<(), StateConflict> {
        self.inner.append(tx)
    }

    /// Appends the transactions into the graph as an atomic unit.
    ///
    /// These transactions can only be selected as a batch, and are reverted and pruned together.
    pub fn append_user_batch(
        &mut self,
        batch: &[Arc<AuthenticatedTransaction>],
    ) -> Result<(), StateConflict> {
        let batch_id =
            BatchId::from_transactions(batch.iter().map(|tx| tx.raw_proven_transaction()));

        // Append each transaction, but revert atomically on error.
        for (idx, tx) in batch.iter().enumerate() {
            if let Err(err) = self.append(Arc::clone(tx)) {
                // We revert in reverse order because inner.revert panics if the node doesn't exist.
                for tx in batch.iter().take(idx).rev() {
                    let reverted = self.inner.revert_node_and_descendants(tx.id());
                    assert_eq!(reverted.len(), 1);
                    assert_eq!(&reverted[0], tx);
                }

                return Err(err);
            }
        }

        let txs = batch.iter().map(GraphNode::id).collect::<Vec<_>>();
        self.user_batches.insert(batch_id, txs);

        Ok(())
    }

    pub fn select_batch(&mut self, budget: BatchBudget) -> Option<SelectedBatch> {
        self.select_user_batch().or_else(|| self.select_internal_batch(budget))
    }

    fn select_user_batch(&mut self) -> Option<SelectedBatch> {
        let candidate_batches = self.user_batches.batches().copied().collect::<HashSet<_>>();
        for candidate in candidate_batches {
            if let Some(batch) = self.try_select_user_batch_candidate(candidate) {
                return Some(batch);
            }
        }

        None
    }

    /// Attempts to select all transactions from the candidate user batch.
    ///
    /// This action succeeds if all transactions in the batch can be sequentially selected.
    /// If any transaction cannot be selected, then all previous selections are rolled back,
    /// and `None` is returned. This makes this function atomic.
    ///
    /// Transactions can fail selection if they depend on any external transactions that have
    /// not yet been selected.
    fn try_select_user_batch_candidate(&mut self, candidate: BatchId) -> Option<SelectedBatch> {
        let mut selected = SelectedBatch::builder();

        let txs = self.user_batches.get_txs_contained_in_batch(&candidate)?;

        for tx in txs {
            let Some(tx) = self.inner.selection_candidates().get(&tx).copied() else {
                // Rollback this batch selection since it cannot complete.
                for tx in selected.txs.into_iter().rev() {
                    self.inner.deselect(tx.id());
                }

                return None;
            };
            let tx = Arc::clone(tx);

            self.inner.select_candidate(tx.id());
            selected.push(tx);
        }

        assert!(!selected.is_empty(), "User batch should not be empty");
        Some(selected.build())
    }

    fn select_internal_batch(&mut self, mut budget: BatchBudget) -> Option<SelectedBatch> {
        let mut selected = SelectedBatch::builder();

        loop {
            // Select arbitrary candidate which is _not_ part of a user batch.
            let candidates = self.inner.selection_candidates();
            let Some(candidate) =
                candidates.values().find(|tx| !self.user_batches.contains_tx(&tx.id()))
            else {
                break;
            };

            if budget.check_then_subtract(candidate) == BudgetStatus::Exceeded {
                break;
            }

            let candidate = Arc::clone(candidate);
            self.inner.select_candidate(candidate.id());
            selected.push(candidate);
        }

        if selected.is_empty() {
            return None;
        }
        let selected = selected.build();

        Some(selected)
    }

    /// Reverts expired transactions and their descendants.
    ///
    /// This is because we don't distinguish between committed and selected transactions. If we
    /// didn't ignore selected transactions here, we would revert committed ones as well, which
    /// breaks the state.
    ///
    /// Returns the identifiers of transactions that were removed from the graph.
    ///
    /// # Note
    ///
    /// Since this _ignores_ selected transactions, and the purpose is to revert expired
    /// transactions after a block is committed, the caller **must** ensure that selected
    /// transactions from expired batches (and therefore not committed) are deselected
    /// _before_ calling this function. i.e. first revert expired batches and deselect their
    /// transactions, then call this.
    pub fn revert_expired(&mut self, chain_tip: BlockNumber) -> HashSet<TransactionId> {
        let mut to_revert = self.inner.expired(chain_tip);
        to_revert.retain(|tx| !self.inner.is_selected(tx));

        let mut reverted = HashSet::with_capacity(to_revert.len());

        for tx in to_revert {
            reverted.extend(&self.revert_tx_and_descendants(tx));
        }

        reverted
    }

    /// Reverts the given transaction and _all_ its descendants _IFF_ it is present in the graph.
    ///
    /// This includes batches that have been marked as proven.
    ///
    /// Returns the reverted transactions in the _reverse_ chronological order they were appended
    /// in.
    pub fn revert_tx_and_descendants(&mut self, transaction: TransactionId) -> Vec<TransactionId> {
        // This is a bit more involved because we also need to atomically revert user batches.
        let mut to_revert = vec![transaction];
        let mut reverted = Vec::new();

        while let Some(revert) = to_revert.pop() {
            // We need this check because `inner.revert..` panics if the node is unknown.
            //
            // And this transaction might already have been reverted as part of descendents in a
            // prior loop.
            if !self.inner.contains(&revert) {
                continue;
            }

            let reverted_now = self.inner.revert_node_and_descendants(revert);

            // Clean up book keeping and also revert transactions from the same user batch, if any.
            for tx in &reverted_now {
                self.failures.remove(&tx.id());

                // Note that this is a pretty rough shod approach. We just dump the entire batch of
                // transactions in, which will result in at least the current transaction being
                // duplicated in `to_revert`. This isn't a concern though since we skip already
                // processed transactions at the top of the loop.
                if let Some(batch_id) = self.user_batches.get_batch_containing_tx(&tx.id()).copied()
                {
                    let batch_txs = self.user_batches.remove(&batch_id);
                    to_revert.extend_from_slice(&batch_txs);
                }
            }

            reverted.extend(reverted_now.into_iter().map(|tx| tx.id()));
        }

        reverted
    }

    /// Marks the batch's transactions as ready for selection again.
    ///
    /// # Panics
    ///
    /// Panics if the given batch has any child batches which are still in flight.
    pub fn requeue_transactions(&mut self, batch: &SelectedBatch) {
        for tx in batch.transactions().iter().rev() {
            self.inner.deselect(tx.id());
        }
    }

    /// Increments each transaction's failure counter, and reverts transactions which exceed the
    /// failure limit.
    ///
    /// This weeds out transactions which participate in batch and block failures, and might be the
    /// root cause.
    ///
    /// # Returns
    ///
    /// Returns the set of reverted transactions.
    pub fn increment_failure_count(
        &mut self,
        txs: impl Iterator<Item = TransactionId>,
    ) -> HashSet<TransactionId> {
        let mut to_revert = Vec::default();

        for tx in txs {
            let count = self.failures.entry(tx).or_default();
            *count += 1;

            if *count >= Self::FAILURE_LIMIT {
                to_revert.push(tx);
            }
        }

        let mut reverted = HashSet::default();
        for tx in to_revert {
            reverted.extend(self.revert_tx_and_descendants(tx));
        }

        reverted
    }

    /// Prunes the given given batch's transactions.
    ///
    /// # Panics
    ///
    /// Panics if the transactions do not exist, or has existing ancestors in the transaction
    /// graph.
    pub fn prune(&mut self, batch: &SelectedBatch) {
        for tx in batch.transactions() {
            self.mark_committed_notes_authenticated_for_descendants(tx);
            self.inner.prune(tx.id());
            self.failures.remove(&tx.id());
        }
        self.user_batches.remove(&batch.id());
    }

    fn mark_committed_notes_authenticated_for_descendants(
        &mut self,
        tx: &Arc<AuthenticatedTransaction>,
    ) {
        let output_notes = tx.output_note_ids().collect::<HashSet<_>>();
        if output_notes.is_empty() {
            return;
        }

        let tx_id = tx.id();
        let descendants = self.inner.descendants(&tx_id);
        for descendant in descendants.into_iter().filter(|descendant| *descendant != tx_id) {
            if let Some(descendant) = self.inner.get_mut(&descendant) {
                Arc::make_mut(descendant).mark_notes_authenticated(output_notes.iter().copied());
            }
        }
    }

    /// Number of transactions which have not been selected for inclusion in a batch.
    pub fn unselected_count(&self) -> usize {
        self.inner.node_count() - self.inner.selected_count()
    }

    /// Total number of transactions in the graph.
    pub fn count(&self) -> usize {
        self.inner.node_count()
    }

    pub fn accounts_count(&self) -> usize {
        self.inner.account_count()
    }

    pub fn nullifier_count(&self) -> usize {
        self.inner.nullifier_count()
    }

    pub fn output_note_count(&self) -> usize {
        self.inner.output_note_count()
    }
}

// BIJECTIVE <USER BATCH, TRANSACTION> MAP
// ================================================================================================

/// A bijective mapping of batches and their transactions.
#[derive(Clone, Debug, PartialEq, Default)]
struct BatchTxMap {
    by_batch: HashMap<BatchId, Vec<TransactionId>>,
    by_tx: HashMap<TransactionId, BatchId>,
}

impl BatchTxMap {
    fn insert(&mut self, batch: BatchId, txs: Vec<TransactionId>) {
        for tx in &txs {
            assert!(self.by_tx.insert(*tx, batch).is_none());
        }
        assert!(self.by_batch.insert(batch, txs).is_none());
    }

    fn remove(&mut self, batch: &BatchId) -> Vec<TransactionId> {
        let txs = self.by_batch.remove(batch).unwrap_or_default();
        for tx in &txs {
            self.by_tx.remove(tx);
        }
        txs
    }

    fn batches(&self) -> impl Iterator<Item = &BatchId> {
        self.by_batch.keys()
    }

    /// Returns the [`BatchId`] mapped to this transaction, if any.
    fn get_batch_containing_tx(&self, tx: &TransactionId) -> Option<&BatchId> {
        self.by_tx.get(tx)
    }

    fn get_txs_contained_in_batch(&self, batch: &BatchId) -> Option<&[TransactionId]> {
        self.by_batch.get(batch).map(Vec::as_slice)
    }

    fn contains_tx(&self, tx: &TransactionId) -> bool {
        self.by_tx.contains_key(tx)
    }
}
