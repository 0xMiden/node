use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OutputNote, TransactionId};

use crate::domain::batch::{BatchParameters, SelectedBatch};
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::StateConflict;
use crate::mempool::BatchBudget;
use crate::mempool::budget::BudgetStatus;
use crate::mempool::graph::dag::Graph;
use crate::mempool::graph::node::GraphNode;

enum BatchSelection {
    Empty,
    Partial(SelectedBatch),
    Full(SelectedBatch),
}

impl BatchSelection {
    fn into_batch(self) -> Option<SelectedBatch> {
        match self {
            Self::Empty => None,
            Self::Partial(batch) | Self::Full(batch) => Some(batch),
        }
    }
}

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

/// Tracks standalone transactions and transactions from user-proven batches.
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

/// Transactions removed by a single lifecycle transition.
///
/// `direct` contains the transactions which triggered the removal. `removed` additionally contains
/// transactions which were removed because they depended on a direct transaction.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct TransactionRemoval {
    direct: BTreeSet<TransactionId>,
    removed: BTreeSet<TransactionId>,
}

impl TransactionRemoval {
    pub(crate) fn direct(&self) -> impl Iterator<Item = TransactionId> + '_ {
        self.direct.iter().copied()
    }

    pub(crate) fn dependents(&self) -> impl Iterator<Item = TransactionId> + '_ {
        self.removed.difference(&self.direct).copied()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.removed.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, transaction_id: &TransactionId) -> bool {
        self.removed.contains(transaction_id)
    }
}

impl TransactionGraph {
    /// Transactions are evicted after failing this number of times.
    pub const FAILURE_LIMIT: u32 = 3;

    pub fn append(&mut self, tx: Arc<AuthenticatedTransaction>) -> Result<(), StateConflict> {
        self.inner.append(tx)
    }

    /// Returns the transaction and output note that created the specified note ID.
    pub fn output_note(&self, note_id: Word) -> Option<(TransactionId, &OutputNote)> {
        let creator = self.inner.note_creator(&note_id)?;
        let output_note = creator
            .raw_proven_transaction()
            .output_notes()
            .iter()
            .find(|note| note.id().as_word() == note_id)
            .expect("the note creator must contain the indexed output note");

        Some((creator.id(), output_note))
    }

    /// Appends a user-proven batch to the graph as an atomic unit.
    ///
    /// These transactions can only be selected as a batch, and are reverted and pruned together.
    pub fn append_user_batch(
        &mut self,
        batch: &[Arc<AuthenticatedTransaction>],
        parameters: BatchParameters,
        proof: Arc<ProvenBatch>,
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
        self.user_batches.insert(batch_id, txs, parameters, proof);

        Ok(())
    }

    pub fn select_any_internal_batch(
        &mut self,
        budget: BatchBudget,
        internal_parameters: BatchParameters,
    ) -> Option<SelectedBatch> {
        self.select_internal_batch(budget, internal_parameters).into_batch()
    }

    pub fn select_full_internal_batch(
        &mut self,
        budget: BatchBudget,
        internal_parameters: BatchParameters,
    ) -> Option<SelectedBatch> {
        match self.select_internal_batch(budget, internal_parameters) {
            BatchSelection::Full(batch) => Some(batch),
            BatchSelection::Partial(batch) => {
                // Full-batch selection is speculative; partial selections must not reserve txs.
                self.deselect_batch(batch);
                None
            },
            BatchSelection::Empty => None,
        }
    }

    fn deselect_batch(&mut self, batch: SelectedBatch) {
        for tx in batch.into_transactions().into_iter().rev() {
            self.inner.deselect(tx.id());
        }
    }

    pub fn select_user_batch(&mut self) -> Option<(SelectedBatch, Arc<ProvenBatch>)> {
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
    fn try_select_user_batch_candidate(
        &mut self,
        candidate: BatchId,
    ) -> Option<(SelectedBatch, Arc<ProvenBatch>)> {
        let (txs, parameters, proof) = self.user_batches.get(&candidate)?;
        let proof = Arc::clone(proof);
        let mut selected = SelectedBatch::builder(parameters);

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
        Some((selected.build(), proof))
    }

    fn select_internal_batch(
        &mut self,
        mut budget: BatchBudget,
        parameters: BatchParameters,
    ) -> BatchSelection {
        let mut selected = SelectedBatch::builder(parameters);

        'outer: loop {
            // Select arbitrary candidate which is _not_ part of a user batch.
            let candidates = self.inner.selection_candidates();

            for tx in candidates.values().filter(|tx| !self.user_batches.contains_tx(&tx.id())) {
                if budget.check_then_subtract(tx) == BudgetStatus::Exceeded {
                    assert!(
                        !selected.is_empty(),
                        "selectable transaction {} exceeds the batch budget; \
                         candidate resources: transactions=1, accounts=1, input_notes={}, \
                         output_notes={}; batch budget: {:?}",
                        tx.id(),
                        tx.input_note_count(),
                        tx.output_note_count(),
                        budget,
                    );

                    continue;
                }

                let candidate = Arc::clone(tx);
                self.inner.select_candidate(candidate.id());
                selected.push(candidate);
                continue 'outer;
            }

            break;
        }

        if selected.is_empty() {
            BatchSelection::Empty
        } else if budget.is_exhausted() {
            // The selected transactions may exactly consume the budget without another candidate
            // being available to trigger the "would exceed" branch above.
            BatchSelection::Full(selected.build())
        } else {
            BatchSelection::Partial(selected.build())
        }
    }

    /// Reverts expired transactions and their descendants.
    ///
    /// This is because we don't distinguish between committed and selected transactions. If we
    /// didn't ignore selected transactions here, we would revert committed ones as well, which
    /// breaks the state.
    ///
    /// Returns both the directly expired transactions and all transactions removed from the graph,
    /// including their dependents.
    ///
    /// # Note
    ///
    /// Since this _ignores_ selected transactions, and the purpose is to revert expired
    /// transactions after a block is committed, the caller **must** ensure that selected
    /// transactions from expired batches (and therefore not committed) are deselected
    /// _before_ calling this function. i.e. first revert expired batches and deselect their
    /// transactions, then call this.
    pub fn revert_expired(&mut self, chain_tip: BlockNumber) -> TransactionRemoval {
        let direct = self
            .inner
            .expired(chain_tip)
            .into_iter()
            .filter(|tx| !self.inner.is_selected(tx))
            .collect::<BTreeSet<_>>();

        let mut removed = BTreeSet::new();

        for tx in direct.iter().copied() {
            removed.extend(&self.revert_tx_and_descendants(tx));
        }

        TransactionRemoval { direct, removed }
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
    /// Returns both the transactions which reached the failure limit directly and all transactions
    /// removed from the graph, including their dependents.
    pub fn increment_failure_count(
        &mut self,
        txs: impl Iterator<Item = TransactionId>,
    ) -> TransactionRemoval {
        let mut to_revert = Vec::default();

        for tx in txs {
            let count = self.failures.entry(tx).or_default();
            *count += 1;

            if *count >= Self::FAILURE_LIMIT {
                to_revert.push(tx);
            }
        }

        let direct = to_revert.into_iter().collect::<BTreeSet<_>>();
        let mut removed = BTreeSet::new();
        for tx in direct.iter().copied() {
            removed.extend(self.revert_tx_and_descendants(tx));
        }

        TransactionRemoval { direct, removed }
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
        self.user_batches.remove(&batch.id().as_batch_id());
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

    pub fn contains(&self, transaction: &TransactionId) -> bool {
        self.inner.contains(transaction)
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
    by_batch: HashMap<BatchId, UserBatch>,
    by_tx: HashMap<TransactionId, BatchId>,
}

#[derive(Clone, Debug, PartialEq)]
struct UserBatch {
    txs: Vec<TransactionId>,
    parameters: BatchParameters,
    proof: Arc<ProvenBatch>,
}

impl BatchTxMap {
    fn insert(
        &mut self,
        batch: BatchId,
        txs: Vec<TransactionId>,
        parameters: BatchParameters,
        proof: Arc<ProvenBatch>,
    ) {
        for tx in &txs {
            assert!(self.by_tx.insert(*tx, batch).is_none());
        }
        assert!(self.by_batch.insert(batch, UserBatch { txs, parameters, proof }).is_none());
    }

    fn remove(&mut self, batch: &BatchId) -> Vec<TransactionId> {
        let Some(batch) = self.by_batch.remove(batch) else {
            return Vec::new();
        };
        for tx in &batch.txs {
            self.by_tx.remove(tx);
        }
        batch.txs
    }

    fn batches(&self) -> impl Iterator<Item = &BatchId> {
        self.by_batch.keys()
    }

    /// Returns the [`BatchId`] mapped to this transaction, if any.
    fn get_batch_containing_tx(&self, tx: &TransactionId) -> Option<&BatchId> {
        self.by_tx.get(tx)
    }

    fn get(
        &self,
        batch: &BatchId,
    ) -> Option<(&[TransactionId], BatchParameters, &Arc<ProvenBatch>)> {
        self.by_batch
            .get(batch)
            .map(|batch| (batch.txs.as_slice(), batch.parameters, &batch.proof))
    }

    fn contains_tx(&self, tx: &TransactionId) -> bool {
        self.by_tx.contains_key(tx)
    }
}
