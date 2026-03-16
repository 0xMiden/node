use std::collections::HashSet;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::note::{NoteHeader, Nullifier};
use miden_protocol::transaction::InputNoteCommitment;

use super::{Graph, GraphNode};

impl GraphNode for ProvenBatch {
    type Id = BatchId;

    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(
            self.transactions()
                .as_slice()
                .iter()
                .flat_map(|tx| tx.input_notes().iter().map(InputNoteCommitment::nullifier)),
        )
    }

    fn output_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(
            self.transactions()
                .as_slice()
                .iter()
                .flat_map(|tx| tx.output_notes().iter().map(NoteHeader::commitment)),
        )
    }

    fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(
            self.input_notes()
                .iter()
                .filter_map(|note| note.header().map(NoteHeader::commitment)),
        )
    }

    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_> {
        Box::new(self.account_updates().values().map(|update| {
            (
                update.account_id(),
                update.initial_state_commitment(),
                update.final_state_commitment(),
            )
        }))
    }

    fn id(&self) -> Self::Id {
        self.id()
    }
}

/// Tracks [`ProvenBatch`] instances that are pending block inclusion.
///
/// Batches form nodes in the underlying [`Graph`]. Dependencies arise when batches consume or
/// produce intersecting pieces of state (nullifiers, notes, or account commitments). The graph is
/// maintained as a DAG by ensuring that every new batch builds on top of the state produced by the
/// batches already present.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ProvenBatchGraph {
    inner: Graph<ProvenBatch>,
}

impl ProvenBatchGraph {
    /// Inserts the batch into the dependency graph.
    ///
    /// # Panics
    ///
    /// Panics if the batch conflicts with the existing graph state.
    pub fn append(&mut self, batch: &ProvenBatch) {
        self.inner.append(batch);
    }

    /// Removes a root batch from the graph, reverting any state it introduced.
    ///
    /// # Panics
    ///
    /// Panics if the batch still has parents in the graph.
    pub fn pop_root(&mut self, batch: &ProvenBatch) {
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
    pub fn roots(&self) -> HashSet<BatchId> {
        self.inner.roots()
    }
}
