use std::collections::{HashMap, HashSet};
use std::hash::Hash;

mod batch;
mod transaction;

pub use batch::BatchGraph;
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

    /// All output notes created by this node, **including** erased notes. This may not
    /// be strictly necessary but it removes having to worry about reverting batches and blocks
    /// with erased notes -- since these would otherwise have different state impact than the
    /// transactions within them.
    fn output_notes(&self) -> Box<dyn Iterator<Item = Word> + '_>;

    fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_>;

    /// The account state updates caused by this node.
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
    N::Id: Eq + Hash + Copy + std::fmt::Debug,
{
    /// Appends a node to the graph.
    ///
    /// Parent-child edges are inferred from state dependencies:
    /// - A note parent edge exists when this node consumes an unauthenticated note that was created
    ///   by another node already present in the graph.
    /// - An account parent edge exists when this node's account update begins from the commitment
    ///   that a prior node left the account in.
    ///
    /// # Panics
    ///
    /// Panics if the node's state does not build on top of the current graph state, e.g. its
    /// account initial commitment does not match the current graph commitment for that account.
    pub fn append(&mut self, node: &N) {
        let id = node.id();

        // Initialise empty edge sets for the new node so it is always present in the maps.
        self.children.entry(id).or_default();
        self.parents.entry(id).or_default();

        // --- nullifiers -----------------------------------------------------------------------

        for nullifier in node.nullifiers() {
            assert!(
                self.nullifiers.insert(nullifier),
                "Nullifier {nullifier} already exists in the graph"
            );
        }

        // --- output notes ---------------------------------------------------------------------

        for commitment in node.output_notes() {
            assert!(
                self.notes_created.insert(commitment, id).is_none(),
                "Output note commitment {commitment} already exists in the graph"
            );
        }

        // --- unauthenticated notes (note-based parent edges) ----------------------------------

        for commitment in node.unauthenticated_notes() {
            // Wire up the parent edge: the node that created this note is a parent of `id`.
            if let Some(&parent_id) = self.notes_created.get(&commitment) {
                // parent -> id
                self.children.entry(parent_id).or_default().insert(id);
                self.parents.entry(id).or_default().insert(parent_id);
            }

            assert!(
                self.unauthenticated_notes.insert(commitment, id).is_none(),
                "Unauthenticated note commitment {commitment} is already consumed in the graph"
            );
        }

        // --- account updates (account-based parent edges) -------------------------------------

        for (account_id, from, to) in node.account_updates() {
            let state = self.accounts.entry(account_id).or_insert_with(|| {
                // First time we see this account in the graph: the initial commitment serves as
                // the baseline.  There is no owning node yet.
                AccountState {
                    commitment: from,
                    owner: None,
                    pass_through: HashSet::default(),
                }
            });

            if from == to {
                // Pass-through: this node requires the account to be at `from` but does not
                // change it.  It must be processed after whatever node set the commitment to
                // `from`, and before any node that changes it away from `from`.
                assert!(
                    state.commitment == from,
                    "Pass-through node's account commitment {from} does not match the current \
                     graph commitment {:?} for account {account_id}",
                    state.commitment
                );

                // The current owner (if any) is a parent of this pass-through node.
                if let Some(owner_id) = state.owner {
                    self.children.entry(owner_id).or_default().insert(id);
                    self.parents.entry(id).or_default().insert(owner_id);
                }

                state.pass_through.insert(id);
            } else {
                // Non-pass-through: this node transitions the account from `from` to `to`.
                assert!(
                    state.commitment == from,
                    "Node's initial account commitment {from} does not match the current graph \
                     commitment {:?} for account {account_id}",
                    state.commitment
                );

                // The current owner (if any) is a parent.
                if let Some(owner_id) = state.owner {
                    self.children.entry(owner_id).or_default().insert(id);
                    self.parents.entry(id).or_default().insert(owner_id);
                }

                // All current pass-through nodes at the old commitment are parents as well,
                // because `id` must be executed after all of them.
                for &pt_id in &state.pass_through {
                    self.children.entry(pt_id).or_default().insert(id);
                    self.parents.entry(id).or_default().insert(pt_id);
                }

                // Advance state.
                state.commitment = to;
                state.owner = Some(id);
                state.pass_through.clear();
            }
        }
    }

    /// Returns the set of root node IDs — nodes that have no parents in the graph.
    pub fn roots(&self) -> HashSet<N::Id> {
        self.parents
            .iter()
            .filter(|(_, parents)| parents.is_empty())
            .map(|(&id, _)| id)
            .collect()
    }

    /// Removes a root node from the graph and cleans up all state associated with it.
    ///
    /// After removal the node's children have their parent entry for this node cleared, which may
    /// promote some of them to roots.
    ///
    /// # Panics
    ///
    /// Panics if the given node is not a root (i.e. it still has parents).
    pub fn pop_root(&mut self, node: &N) {
        let node_id = node.id();

        let parents = self.parents.remove(&node_id).unwrap_or_default();
        assert!(parents.is_empty(), "Cannot pop node: it still has parents in the graph");

        // Remove this node from its children's parent sets.
        if let Some(children) = self.children.remove(&node_id) {
            for child_id in children {
                if let Some(child_parents) = self.parents.get_mut(&child_id) {
                    child_parents.remove(&node_id);
                }
            }
        }

        // Remove nullifiers created by this node.
        for nullifier in node.nullifiers() {
            assert!(
                self.nullifiers.remove(&nullifier),
                "Nullifier {nullifier} was not present for removal"
            );
        }

        // Remove output notes created by this node.
        for commitment in node.output_notes() {
            assert!(
                self.notes_created.remove(&commitment).is_some(),
                "Output note commitment {commitment} was not present for removal"
            );
        }

        // Remove unauthenticated note entries consumed by this node.
        for commitment in node.unauthenticated_notes() {
            assert!(
                self.unauthenticated_notes.remove(&commitment).is_some(),
                "Unauthenticated note commitment {commitment} was not present for removal"
            );
        }

        // Update account state: remove this node as owner or pass-through from every account.
        for (account, from, to) in node.account_updates() {
            let Some(state) = self.accounts.get_mut(&account) else {
                panic!("Account {account} was not present for removal");
            };

            // A root node is by definition the oldest update an account may have, and therefore
            // its possible that the latest account commitment has changed.
            if state.commitment != to {
                continue;
            }

            if from == to {
                assert!(
                    state.pass_through.remove(&node_id),
                    "Pass through account {account} update was not present for removal"
                );
            } else {
                assert!(
                    state.owner.take_if(|owner| owner == &node_id).is_some(),
                    "Account {account} update was not present for removal"
                );
            }

            // Stop tracking the account if its got no updates left.
            if state.is_empty() {
                self.accounts.remove(&account);
            }
        }
    }

    /// The given account's current commitment in this graph.
    ///
    /// Returns `None` if the account has not been seen by this graph at all.
    pub fn account_commitment(&self, account: &AccountId) -> Option<Word> {
        self.accounts.get(account).map(|state| state.commitment)
    }

    /// Returns `true` if the given nullifier has already been consumed by a node in this graph.
    pub fn nullifier_exists(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Returns `true` if a node in this graph created an output note with the given ID.
    ///
    /// Uses the note's commitment (its `Word` representation) for the lookup.
    pub fn output_note_exists(&self, note: &Word) -> bool {
        self.notes_created.contains_key(note)
    }

    /// Returns `true` if the output note with the given ID has already been consumed as an
    /// unauthenticated input note by another node in this graph.
    pub fn output_note_is_consumed(&self, note: &Word) -> bool {
        self.unauthenticated_notes.contains_key(note)
    }

    /// Returns the IDs of all nodes which depend on the given node.
    pub fn descendents(&self, node: &N::Id) -> HashSet<N::Id> {
        todo!();
    }

    /// Removes the node _IFF_ it is a leaf node (has no descendents).
    pub fn revert_leaf(&self, node: &N::Id) -> Option<N::Id> {
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

impl<K> AccountState<K>
where
    K: Eq + std::hash::Hash,
{
    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.pass_through.is_empty()
    }
}
