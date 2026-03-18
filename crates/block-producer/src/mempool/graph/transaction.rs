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
use crate::mempool::graph::{Graph, GraphNode};

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

    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_> {
        let update = self.account_update();
        Box::new(std::iter::once((
            update.account_id(),
            update.initial_state_commitment(),
            update.final_state_commitment(),
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
    pub fn append(&mut self, tx: Arc<AuthenticatedTransaction>) {
        self.inner.append(&tx);
        self.txs.insert(tx.id(), tx);
    }

    pub fn select_batch(&mut self, mut budget: BatchBudget) -> Option<SelectedBatch> {
        let mut selected = SelectedBatch::builder();

        while let Some(root) = self.inner.roots().iter().next() {
            let tx = self.txs.get(root).expect("TransactionGraph::root must exist");
            if budget.check_then_subtract(tx) == BudgetStatus::Exceeded {
                break;
            }

            let tx = self.txs.remove(root).expect("TransactionGraph::root must exist");
            self.inner.select_root(&tx);
            selected.push(tx);
        }

        if selected.is_empty() {
            return None;
        }
        let selected = selected.build();

        Some(selected)
    }

    pub fn revert_expired(&mut self, chain_tip: BlockNumber) -> HashSet<TransactionId> {
        todo!();
        // let mut reverted = Vec::default();

        // let mut expired = self
        //     .batches
        //     .iter()
        //     .filter_map(|(id, batch)| (batch.expires_at() <= chain_tip).then_some(id))
        //     // TODO: consider selected once they're re-added.
        //     .copied()
        //     .collect::<HashSet<_>>();

        // for batch in expired {
        //     reverted.extend(self.revert_batch_and_descendents(batch));
        // }

        // reverted
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
        descendents.insert(transaction);

        let mut reverted = Vec::new();
        'outer: while !descendents.is_empty() {
            for node in &descendents {
                if let Some(leaf) = self.inner.revert_leaf(node) {
                    descendents.remove(&leaf);
                    self.txs.remove(&leaf).unwrap();
                    reverted.push(leaf);
                    continue 'outer;
                }
            }

            panic!("revert_tx_and_descendents failed to make progress");
        }

        reverted
    }

    pub fn requeue_batch_transactions(&mut self, batch: SelectedBatch) {
        todo!();
    }

    pub fn prune(&mut self, transaction: TransactionId) {
        todo!();
    }

    /// The given account's current commitment in this graph.
    ///
    /// Returns `None` if the account has not been seen by this graph at all.
    pub fn account_commitment(&self, account: &AccountId) -> Option<Word> {
        self.inner.account_commitment(account)
    }

    /// Returns `true` if the given nullifier has already been consumed by a node in this graph.
    pub fn nullifier_exists(&self, nullifier: &Nullifier) -> bool {
        self.inner.nullifier_exists(nullifier)
    }

    /// Returns `true` if a node in this graph created an output note with the given ID.
    ///
    /// Uses the note's commitment (its `Word` representation) for the lookup.
    pub fn output_note_exists(&self, note: &Word) -> bool {
        self.inner.output_note_exists(note)
    }

    /// Returns `true` if the output note with the given ID has already been consumed as an
    /// unauthenticated input note by another node in this graph.
    pub fn output_note_is_consumed(&self, note: &Word) -> bool {
        self.inner.output_note_is_consumed(note)
    }

    /// Total number of transactions in the graph.
    ///
    /// This includes selected and unselected transactions.
    pub fn len(&self) -> usize {
        self.txs.len()
    }
}
