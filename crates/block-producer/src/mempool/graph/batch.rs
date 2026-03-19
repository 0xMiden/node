use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::ops::Not;
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::mempool::BlockBudget;
use crate::mempool::budget::BudgetStatus;
use crate::mempool::graph::StateConflict;
use crate::mempool::graph::graph::Graph;
use crate::mempool::graph::node::GraphNode;

impl GraphNode for SelectedBatch {
    type Id = BatchId;

    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.txs().iter().flat_map(|tx| tx.nullifiers()))
    }

    fn output_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.txs().iter().flat_map(|tx| tx.output_note_commitments()))
    }

    fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.txs().iter().flat_map(|tx| tx.unauthenticated_note_commitments()))
    }

    fn account_updates(
        &self,
    ) -> Box<dyn Iterator<Item = (AccountId, Word, Word, Option<Word>)> + '_> {
        // TODO: store -- this is incorrect
        Box::new(self.account_updates().map(|(account, from, to)| (account, from, to, None)))
    }

    fn id(&self) -> Self::Id {
        self.id()
    }
}

/// Tracks [`SelectedBatch`] instances that are pending proof generation.
///
/// Batches form nodes in the underlying [`Graph`]. Edges between batches capture dependencies
/// introduced by shared resources (nullifiers, notes, and account states). The graph remains a DAG
/// by requiring that each batch builds on top of the state created by previously inserted batches.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct BatchGraph {
    inner: Graph<SelectedBatch>,
    batches: HashMap<BatchId, SelectedBatch>,
    proven: HashMap<BatchId, Arc<ProvenBatch>>,
}

impl BatchGraph {
    /// Inserts the batch into the dependency graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch's state conflicts with the current graph view (e.g. it
    /// consumes a nullifier that was already spent).
    pub fn append(&mut self, batch: &SelectedBatch) -> Result<(), StateConflict> {
        self.inner.append(batch)
    }

    /// Reverts the given batch and _all_ its descendents _IFF_ it is present in the graph.
    ///
    /// This includes batches that have been marked as proven.
    ///
    /// Returns the reverted batches in the _reverse_ chronological order they were appended in.
    pub fn revert_batch_and_descendents(&mut self, batch: BatchId) -> Vec<SelectedBatch> {
        if !self.batches.contains_key(&batch) {
            return Vec::default();
        }

        let mut descendents = self.inner.descendents(&batch);

        let mut reverted = Vec::new();
        'outer: while !descendents.is_empty() {
            for node in descendents.iter().copied() {
                if self.inner.is_leaf(&node) {
                    descendents.remove(&node);
                    let batch = self.batches.remove(&node).unwrap();
                    reverted.push(batch);
                    continue 'outer;
                }
            }

            panic!("revert_batch_and_descendents failed to make progress");
        }

        reverted
    }

    /// Reverts expired batches and their descendents.
    ///
    /// Only unselected batches are considered, the assumption being that selected batches
    /// are in committed blocks and should not be reverted.
    ///
    /// Batches are returned in reverse-chronological order.
    pub fn revert_expired(&mut self, chain_tip: BlockNumber) -> Vec<SelectedBatch> {
        let mut reverted = Vec::default();

        let mut expired = self
            .batches
            .iter()
            .filter(|(id, _)| !self.inner.is_selected(id))
            .filter_map(|(id, batch)| (batch.expires_at() <= chain_tip).then_some(id))
            .copied()
            .collect::<HashSet<_>>();

        for batch in expired {
            reverted.extend(self.revert_batch_and_descendents(batch));
        }

        reverted
    }

    /// Marks the given batch as proven, making it available for selection in a block
    /// once it becomes a root.
    pub fn submit_proof(&mut self, proof: Arc<ProvenBatch>) {
        if self.batches.contains_key(&proof.id()) {
            self.proven.insert(proof.id(), proof);
        }
    }

    pub fn select_block(&mut self, mut budget: BlockBudget) -> Vec<Arc<ProvenBatch>> {
        let mut selected = Vec::default();

        // Only root's which are proven can be selected for inclusion in a block.
        while let Some(candidate) = self
            .inner
            .selection_candidates()
            .iter()
            .find_map(|candidate| self.proven.get(candidate))
        {
            if budget.check_then_subtract(candidate) == BudgetStatus::Exceeded {
                break;
            }

            self.inner.select_candidate(candidate.id());
            selected.push(Arc::clone(candidate));
        }

        selected
    }

    /// Prunes the given batch.
    ///
    /// # Panics
    ///
    /// Panics if the batch does not exist, or has existing ancestors in the batch
    /// graph.
    pub fn prune(&mut self, batch: BatchId) {
        let batch = self.batches.remove(&batch).expect("batch to prune must exist");
        self.inner.prune(&batch);
        self.proven.remove(&batch.id());
    }

    pub fn proven_count(&self) -> usize {
        self.proven.len()
    }

    pub fn proposed_count(&self) -> usize {
        self.batches.len() - self.proven_count()
    }
}
