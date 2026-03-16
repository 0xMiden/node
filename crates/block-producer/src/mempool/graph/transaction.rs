use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::mempool::graph::{Graph, GraphNode};
use crate::mempool::{BatchBudget, budget};

// TRANSACTION GRAPH NODE
// ================================================================================================

impl GraphNode for AuthenticatedTransaction {
    type Id = TransactionId;

    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.nullifiers())
    }

    fn output_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.output_note_commitments())
    }

    fn unauthenticated_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
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
}

impl TransactionGraph {
    pub fn append(&mut self, tx: AuthenticatedTransaction) {
        self.inner.append(&tx);
    }

    pub fn select_batch(&mut self, budget: BatchBudget) -> Option<SelectedBatch> {
        todo!();
    }
}
