use std::collections::HashSet;
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
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
        Box::new(self.output_note_commitments())
    }

    fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.unauthenticated_note_commitments())
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
}

impl TransactionGraph {
    pub fn append(&mut self, tx: Arc<AuthenticatedTransaction>) -> Result<(), StateConflict> {
        self.inner.append(tx)
    }

    pub fn select_batch(&mut self, mut budget: BatchBudget) -> Option<SelectedBatch> {
        let mut selected = SelectedBatch::builder();

        while let Some((id, tx)) = self.inner.selection_candidates().pop_first() {
            if budget.check_then_subtract(tx) == BudgetStatus::Exceeded {
                break;
            }

            selected.push(Arc::clone(tx));
            self.inner.select_candidate(*id);
        }

        if selected.is_empty() {
            return None;
        }
        let selected = selected.build();

        Some(selected)
    }

    /// Reverts expired transactions and their descendants.
    ///
    /// Only unselected transactions are considered; selected transactions are assumed to be in
    /// committed blocks and should not be reverted.
    ///
    /// Returns the identifiers of transactions that were removed from the graph.
    pub fn revert_expired(&mut self, chain_tip: BlockNumber) -> HashSet<TransactionId> {
        self.inner
            .revert_expired_unselected(chain_tip)
            .into_iter()
            .map(|tx| tx.id())
            .collect()
    }

    /// Reverts the given transaction and _all_ its descendants _IFF_ it is present in the graph.
    ///
    /// This includes batches that have been marked as proven.
    ///
    /// Returns the reverted batches in the _reverse_ chronological order they were appended in.
    pub fn revert_tx_and_descendants(&mut self, transaction: TransactionId) -> Vec<TransactionId> {
        // We need this check because `inner.revert..` panics if the node is unknown.
        if !self.inner.contains(&transaction) {
            return Vec::default();
        }

        self.inner
            .revert_node_and_descendants(transaction)
            .into_iter()
            .map(|tx| tx.id())
            .collect()
    }

    /// Marks the batch's transactions are ready for selection again.
    ///
    /// # Panics
    ///
    /// Panics if the given batch has any child batches which are still in flight.
    pub fn requeue_transactions(&mut self, batch: SelectedBatch) {
        for tx in batch.into_transactions().iter().rev() {
            self.inner.deselect(tx.id());
        }
    }

    /// Prunes the given transaction.
    ///
    /// # Panics
    ///
    /// Panics if the transaction does not exist, or has existing ancestors in the transaction
    /// graph.
    pub fn prune(&mut self, transaction: TransactionId) {
        self.inner.prune(transaction);
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
