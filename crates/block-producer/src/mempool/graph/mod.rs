use std::collections::{HashMap, HashSet};
use std::hash::Hash;

mod transaction;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::{NoteId, Nullifier};
pub use transaction::TransactionGraph;

trait GraphNode {
    type Id;

    fn id(&self) -> Self::Id;

    /// All [`Nullifier`]s created by this node, **including** nullifiers for erased notes. This
    /// may not be strictly necessary but it removes having to worry about reverting batches and
    /// blocks with erased notes -- since these would otherwise have different state impact than
    /// the transactions within them.
    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_>;

    /// All output note commitments created by this node, **including** erased notes. This may not
    /// be strictly necessary but it removes having to worry about reverting batches and blocks
    /// with erased notes -- since these would otherwise have different state impact than the
    /// transactions within them.
    fn output_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_>;

    fn unauthenticated_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_>;

    /// The account state commitment updates caused by this node.
    ///
    /// Output tuple represents each updates `(account ID, initial commitment, final commitment)`.
    ///
    /// Updates must be aggregates i.e. only a single account ID update allowed.
    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_>;
}

#[derive(Clone, Debug, PartialEq)]
struct Graph<N>
where
    N: GraphNode,
    N::Id: Eq + std::hash::Hash,
{
    children: HashMap<N::Id, HashSet<N::Id>>,
    parents: HashMap<N::Id, HashSet<N::Id>>,
    nullifiers: HashSet<Nullifier>,
    notes_created: HashMap<Word, N::Id>,
    unauthenticated_notes: HashMap<Word, N::Id>,
    accounts: HashMap<AccountId, AccountState<N::Id>>,
}

impl<N> Default for Graph<N>
where
    N: GraphNode,
    N::Id: Eq + std::hash::Hash,
{
    fn default() -> Self {
        Self {
            children: HashMap::default(),
            parents: HashMap::default(),
            nullifiers: HashSet::default(),
            notes_created: HashMap::default(),
            unauthenticated_notes: HashMap::default(),
            accounts: HashMap::default(),
        }
    }
}

impl<N> Graph<N>
where
    N: GraphNode,
    N::Id: Eq + std::hash::Hash,
{
    /// Panics if the incoming state does not build on top of the current state.
    pub fn append(&mut self, node: &N) {
        todo!();
    }

    pub fn roots(&self) -> HashSet<N::Id> {
        todo!();
    }

    pub fn pop_root(&self, node: N::Id) {
        todo!();
    }

    /// The given account's current commitment in this graph.
    pub fn account_commitment(&self, account: &AccountId) -> Option<Word> {
        todo!();
    }

    pub fn nullifier_exists(&self, nullifier: &Nullifier) -> bool {
        todo!();
    }

    pub fn output_note_exists(&self, note: &NoteId) -> bool {
        todo!();
    }

    pub fn output_note_is_consumed(&self, note: &NoteId) -> bool {
        todo!();
    }
}

#[derive(Clone, Debug, PartialEq)]
struct AccountState<K>
where
    K: Eq + std::hash::Hash,
{
    commitment: Word,
    owner: Option<K>,
    pass_through: HashSet<K>,
}
