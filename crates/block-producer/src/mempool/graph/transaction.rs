use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::mempool::BatchBudget;
use crate::mempool::budget::BudgetStatus;
use crate::mempool::graph::StateConflict;
use crate::mempool::graph::graph::Graph;
use crate::mempool::graph::node::GraphNode;

// TRANSACTION GRAPH NODE
// ================================================================================================

impl GraphNode for AuthenticatedTransaction {
    type Id = TransactionId;

    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.nullifiers())
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
        self.id()
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
    inner: Graph<AuthenticatedTransaction>,
    txs: HashMap<TransactionId, Arc<AuthenticatedTransaction>>,
}

impl TransactionGraph {
    pub fn append(&mut self, tx: Arc<AuthenticatedTransaction>) -> Result<(), StateConflict> {
        self.inner.append(&tx)?;
        self.txs.insert(tx.id(), tx);
        Ok(())
    }

    pub fn select_batch(&mut self, mut budget: BatchBudget) -> Option<SelectedBatch> {
        let mut selected = SelectedBatch::builder();

        while let Some(candidate) = self.inner.selection_candidates().iter().next() {
            let tx = self.txs.get(candidate).expect("transaction in graph must have data");
            if budget.check_then_subtract(tx) == BudgetStatus::Exceeded {
                break;
            }

            self.inner.select_candidate(tx.id());
            selected.push(Arc::clone(tx));
        }

        if selected.is_empty() {
            return None;
        }
        let selected = selected.build();

        Some(selected)
    }

    /// Reverts expired transactions and their descendents.
    ///
    /// Only unselected transactions are considered, the assumption being that selected transactions
    /// are in committed blocks and should not be reverted.
    pub fn revert_expired(&mut self, chain_tip: BlockNumber) -> HashSet<TransactionId> {
        let mut reverted = HashSet::default();

        let mut expired = self
            .txs
            .iter()
            .filter(|(id, _)| !self.inner.is_selected(id))
            .filter_map(|(id, tx)| (tx.expires_at() <= chain_tip).then_some(id))
            .copied()
            .collect::<HashSet<_>>();

        for transaction in expired {
            reverted.extend(self.revert_tx_and_descendents(transaction));
        }

        reverted
    }

    /// Reverts the given transaction and _all_ its descendents _IFF_ it is present in the graph.
    ///
    /// This includes batches that have been marked as proven.
    ///
    /// Returns the reverted batches in the _reverse_ chronological order they were appended in.
    pub fn revert_tx_and_descendents(&mut self, transaction: TransactionId) -> Vec<TransactionId> {
        if !self.txs.contains_key(&transaction) {
            return Vec::default();
        }

        let mut descendents = self.inner.descendents(&transaction);

        let mut reverted = Vec::new();
        'outer: while !descendents.is_empty() {
            for node in descendents.iter().copied() {
                if self.inner.is_leaf(&node) {
                    descendents.remove(&node);
                    self.txs.remove(&node).unwrap();
                    reverted.push(node);
                    continue 'outer;
                }
            }

            panic!("revert_tx_and_descendents failed to make progress");
        }

        reverted
    }

    /// Marks the batch's transactions are ready for selection again.
    ///
    /// # Panics
    ///
    /// Panics if the given batch has any child batches which are still in flight.
    pub fn requeue_transactions(&mut self, batch: SelectedBatch) {
        for tx in batch.into_transactions().iter().rev() {
            self.inner.deselect(&tx.id());
        }
    }

    /// Prunes the given transaction.
    ///
    /// # Panics
    ///
    /// Panics if the transaction does not exist, or has existing ancestors in the transaction
    /// graph.
    pub fn prune(&mut self, transaction: TransactionId) {
        let transaction = self.txs.remove(&transaction).expect("transaction to prune must exist");
        self.inner.prune(&transaction);
    }

    /// Number of transactions which have not been selected for inclusion in a batch.
    pub fn unselected_count(&self) -> usize {
        self.txs.len() - self.inner.selected_count()
    }
}
