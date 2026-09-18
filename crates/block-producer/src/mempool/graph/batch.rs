use std::collections::HashMap;
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::domain::batch::{SelectedBatch, SelectedBatchId};
use crate::errors::StateConflict;
use crate::mempool::BlockBudget;
use crate::mempool::budget::BudgetStatus;
use crate::mempool::graph::dag::Graph;
use crate::mempool::graph::node::GraphNode;

// BATCH IMPL FOR GRAPH NODE
// ================================================================================================

impl GraphNode for SelectedBatch {
    type Id = SelectedBatchId;

    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.transactions().iter().flat_map(|tx| tx.nullifiers()))
    }

    fn output_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.transactions().iter().flat_map(|tx| tx.output_note_ids()))
    }

    fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.unauthenticated_note_commitments())
    }

    fn account_updates(
        &self,
    ) -> Box<dyn Iterator<Item = (AccountId, Word, Word, Option<Word>)> + '_> {
        Box::new(self.account_updates())
    }

    fn id(&self) -> Self::Id {
        self.id()
    }

    fn expires_at(&self) -> BlockNumber {
        self.expires_at()
    }
}

// BATCH GRAPH
// ================================================================================================

/// Tracks [`SelectedBatch`] instances that are waiting for inclusion in a block.
///
/// Batches form nodes in the underlying [`Graph`]. Edges between batches capture dependencies
/// introduced by shared resources (nullifiers, notes, and account states). The graph remains a DAG
/// by requiring that each batch builds on top of the state created by previously inserted batches.
/// Sequencer-built batches wait for a proof. User-proven batches include their proof when inserted.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct BatchGraph {
    inner: Graph<SelectedBatch>,
    proven: HashMap<SelectedBatchId, Arc<ProvenBatch>>,
    selected_by_proven: HashMap<BatchId, SelectedBatchId>,
}

impl BatchGraph {
    /// Inserts the batch into the dependency graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch's state conflicts with the current graph view (e.g. it
    /// consumes a nullifier that was already spent).
    pub fn append(&mut self, batch: SelectedBatch) -> Result<(), StateConflict> {
        self.inner.append(batch)
    }

    /// Inserts a user-proven batch into the dependency graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch state conflicts with the current graph view.
    pub fn append_user_batch(
        &mut self,
        batch: SelectedBatch,
        proof: Arc<ProvenBatch>,
    ) -> Result<(), StateConflict> {
        let selected_id = batch.id();
        assert_eq!(
            selected_id.as_batch_id(),
            proof.id(),
            "a user proof must match its selected batch",
        );

        self.inner.append(batch)?;
        self.insert_proof(selected_id, proof.id(), proof);

        Ok(())
    }

    /// Reverts the given batch and _all_ its descendants _IFF_ it is present in the graph.
    ///
    /// This includes batches that have been marked as proven.
    ///
    /// Returns the reverted batches in the _reverse_ chronological order they were appended in.
    pub fn revert_selected_batch_and_descendants(
        &mut self,
        batch: SelectedBatchId,
    ) -> Vec<SelectedBatch> {
        // We need this check because `inner.revert..` panics if the node is unknown.
        if !self.inner.contains(&batch) {
            return Vec::default();
        }

        let reverted = self.inner.revert_node_and_descendants(batch);
        for batch in &reverted {
            if let Some(proven) = self.proven.remove(&batch.id()) {
                self.selected_by_proven.remove(&proven.id());
            }
        }

        reverted
    }

    /// Reverts the proven batch and all its descendants if it is present in the graph.
    pub fn revert_proven_batch_and_descendants(&mut self, batch: BatchId) -> Vec<SelectedBatch> {
        let Some(selected_id) = self.selected_by_proven.get(&batch).copied() else {
            return Vec::new();
        };

        self.revert_selected_batch_and_descendants(selected_id)
    }

    /// Reverts expired batches and their descendants.
    ///
    /// Only unselected batches are considered, the assumption being that selected batches
    /// are in committed blocks and should not be reverted.
    ///
    /// Batches are returned in reverse-chronological order.
    pub fn revert_expired(&mut self, chain_tip: BlockNumber) -> Vec<SelectedBatch> {
        // We only revert batches which are _not_ included in blocks.
        let mut to_revert = self.inner.expired(chain_tip);
        to_revert.retain(|batch| !self.inner.is_selected(batch));

        let mut reverted = Vec::with_capacity(to_revert.len());

        for batch in to_revert {
            reverted.extend_from_slice(&self.revert_selected_batch_and_descendants(batch));
        }

        reverted
    }

    /// Marks the given batch as proven, making it available for selection in a block once it
    /// becomes a root.
    pub fn submit_proof(&mut self, proof: Arc<ProvenBatch>) {
        let proof_id = proof.id();
        let (_builder_transaction, selected_transactions) = proof
            .transactions()
            .as_slice()
            .split_last()
            .expect("a builder batch must contain a batch builder transaction");
        assert!(
            !selected_transactions.is_empty(),
            "a builder batch must contain at least one user transaction",
        );
        let selected_id = SelectedBatchId::from_batch_id(BatchId::from_ids(
            selected_transactions
                .iter()
                .map(|transaction| (transaction.id(), transaction.account_id())),
        ));

        self.insert_proof(selected_id, proof_id, proof);
    }

    fn insert_proof(
        &mut self,
        selected_id: SelectedBatchId,
        proof_id: BatchId,
        proof: Arc<ProvenBatch>,
    ) {
        if self.inner.contains(&selected_id) {
            if let Some(previous) = self.proven.get(&selected_id) {
                self.selected_by_proven.remove(&previous.id());
            }
            self.selected_by_proven.insert(proof_id, selected_id);
            self.proven.insert(selected_id, proof);
        }
    }

    /// Returns `true` if the batch has been proven previously.
    pub fn is_proven(&mut self, batch: &SelectedBatchId) -> bool {
        self.proven.contains_key(batch)
    }

    /// Selects a set of batches for inclusion in the next block.
    ///
    /// A batch is available for selection if:
    /// - all the batches it depends on have been selected for a previous block, or are selected in
    ///   this block as well, and
    /// - the batch has had a proof submitted
    pub fn select_block(&mut self, mut budget: BlockBudget) -> Vec<Arc<ProvenBatch>> {
        let mut selected = Vec::default();

        // Only batches which are proven can be selected for inclusion in a block.
        while let Some((selected_id, candidate)) = self
            .inner
            .selection_candidates()
            .iter()
            .find_map(|(id, _)| self.proven.get(id).map(|proof| (**id, proof)))
        {
            if budget.check_then_subtract(candidate) == BudgetStatus::Exceeded {
                break;
            }

            self.inner.select_candidate(selected_id);
            selected.push(Arc::clone(candidate));
        }

        selected
    }

    /// Prunes the given batch and returns it.
    ///
    /// # Panics
    ///
    /// Panics if the batch does not exist, or has existing ancestors in the batch
    /// graph.
    pub fn prune(&mut self, batch: BatchId) -> SelectedBatch {
        let selected_id = self
            .selected_by_proven
            .remove(&batch)
            .expect("proven batch must map to a selected batch");
        if let Some(proven) = self.proven.remove(&selected_id) {
            self.selected_by_proven.remove(&proven.id());
        }
        self.inner.prune(selected_id)
    }

    pub fn proven_count(&self) -> usize {
        self.proven.keys().filter(|batch| !self.inner.is_selected(batch)).count()
    }

    pub fn proposed_count(&self) -> usize {
        self.inner
            .node_count()
            .checked_sub(self.proven.len())
            .expect("proven batches cannot exceed total batches")
    }
}
