use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::BatchId;
use miden_protocol::note::Nullifier;

use super::{Graph, GraphNode};
use crate::domain::batch::SelectedBatch;

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

    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_> {
        Box::new(self.account_updates())
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
pub struct SelectedBatchGraph {
    inner: Graph<SelectedBatch>,
}

impl SelectedBatchGraph {
    /// Inserts the batch into the dependency graph.
    ///
    /// # Panics
    ///
    /// Panics if the batch's state conflicts with the current graph view (e.g. it consumes a
    /// nullifier that was already spent).
    pub fn append(&mut self, batch: &SelectedBatch) {
        self.inner.append(batch);
    }

    /// Removes a root batch from the graph, reverting any state it introduced.
    ///
    /// # Panics
    ///
    /// Panics if the batch still has parents in the graph.
    pub fn pop_root(&mut self, batch: &SelectedBatch) {
        self.inner.pop_root(batch);
    }

    /// Returns the most recent commitment known for the specified account.
    pub fn account_commitment(&self, account: &AccountId) -> Option<Word> {
        self.inner.account_commitment(account)
    }

    /// Returns `true` if the given nullifier has already been consumed.
    pub fn nullifier_exists(&self, nullifier: &Nullifier) -> bool {
        self.inner.nullifier_exists(nullifier)
    }

    /// Returns `true` if an output note with the given commitment has been created.
    pub fn output_note_exists(&self, note: &Word) -> bool {
        self.inner.output_note_exists(note)
    }

    /// Returns `true` if the output note with the given commitment has been consumed as an
    /// unauthenticated input.
    pub fn output_note_is_consumed(&self, note: &Word) -> bool {
        self.inner.output_note_is_consumed(note)
    }

    /// Returns the set of batches that currently have no dependencies.
    pub fn roots(&self) -> std::collections::HashSet<BatchId> {
        self.inner.roots()
    }
}
