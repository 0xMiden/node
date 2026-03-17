use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Not;
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::note::Nullifier;

use super::{Graph, GraphNode};
use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;

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
pub struct BatchGraph {
    inner: Graph<SelectedBatch>,
    batches: HashMap<BatchId, SelectedBatch>,
    proven: HashMap<BatchId, Arc<ProvenBatch>>,
}

impl BatchGraph {
    /// Inserts the batch into the dependency graph.
    ///
    /// # Panics
    ///
    /// Panics if the batch's state conflicts with the current graph view (e.g. it consumes a
    /// nullifier that was already spent).
    pub fn append(&mut self, batch: &SelectedBatch) {
        self.inner.append(batch);
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
        descendents.insert(batch);

        let mut reverted = Vec::new();
        'outer: while !descendents.is_empty() {
            for node in &descendents {
                if let Some(leaf) = self.inner.revert_leaf(node) {
                    descendents.remove(&leaf);
                    reverted.push(self.batches.remove(&leaf).unwrap());
                    continue 'outer;
                }
            }

            panic!("revert_batch_and_descendents failed to make progress");
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
}
