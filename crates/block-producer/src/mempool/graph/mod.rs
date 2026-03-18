use std::collections::{HashMap, HashSet};
use std::hash::Hash;

mod batch;
mod transaction;

pub use batch::BatchGraph;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::Nullifier;
use thiserror::Error;
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

    /// Input notes which were not authenticated against any committed block thus far.
    ///
    /// Such notes are not yet known to exist by us (in the store) and must therefore be the output
    /// of another node currently in flight in the graph in order to be considered valid.
    fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_>;

    /// The account state updates caused by this node.
    ///
    /// Output tuple represents each updates `(account ID, initial commitment, final commitment,
    /// store commitment)`.
    ///
    /// Updates must be aggregates i.e. only a single account ID update allowed.
    fn account_updates(
        &self,
    ) -> Box<dyn Iterator<Item = (AccountId, Word, Word, Option<Word>)> + '_>;
}

#[derive(Clone, Debug, PartialEq)]
struct Graph<N>
where
    N: GraphNode,
    N::Id: Eq + std::hash::Hash,
{
    children: HashMap<N::Id, HashSet<N::Id>>,
    parents: HashMap<N::Id, HashSet<N::Id>>,
    selected: HashSet<N::Id>,
    nullifiers: HashSet<Nullifier>,
    notes_created: HashMap<Word, N::Id>,
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
            selected: HashSet::default(),
            nullifiers: HashSet::default(),
            notes_created: HashMap::default(),
            accounts: HashMap::default(),
        }
    }
}

impl<N> Graph<N>
where
    N: GraphNode,
    N::Id: Eq + Hash + Copy + std::fmt::Display,
{
    /// Appends a node to the graph.
    ///
    /// Parent-child edges are inferred from state dependencies:
    /// - A note parent edge exists when this node consumes an unauthenticated note that was created
    ///   by the parent node.
    /// - An account parent edge exists when this node's account update begins from the commitment
    ///   that the parent node transitioned the account to.
    ///
    /// # Errors
    ///
    /// Returns an error if the node's state does not build on top of the current graph state.
    pub fn append(&mut self, node: &N) -> Result<(), StateConflict> {
        self.validate_append(node)?;
        self.apply_append(node);
        Ok(())
    }

    /// Verifies that the node can be appended ontop of the existing graph state.
    ///
    /// This **only** performs the check -- it takes a non-exclusive reference (`&self`).
    ///
    /// This _must_ be called immedietely prior to [`apply_append`], which performs the actual
    /// node insertion (under the assumption that this check was already performed).
    ///
    /// # Errors
    ///
    /// See [`StateConflict`] for the error conditions.
    fn validate_append(&self, node: &N) -> Result<(), StateConflict> {
        let duplicate_nullifiers = node
            .nullifiers()
            .filter(|nullifier| self.nullifiers.contains(nullifier))
            .collect::<Vec<_>>();
        if !duplicate_nullifiers.is_empty() {
            return Err(StateConflict::NullifiersAlreadyExist(duplicate_nullifiers));
        }

        let duplicate_output_notes = node
            .output_notes()
            .filter(|note| self.notes_created.contains_key(note))
            .collect::<Vec<_>>();
        if !duplicate_output_notes.is_empty() {
            return Err(StateConflict::OutputNotesAlreadyExist(duplicate_output_notes));
        }

        let missing_input_notes = node
            .unauthenticated_notes()
            .filter(|note| !self.notes_created.contains_key(note))
            .collect::<Vec<_>>();
        if !missing_input_notes.is_empty() {
            return Err(StateConflict::UnauthenticatedNotesMissing(missing_input_notes));
        }

        for (account_id, from, to, store) in node.account_updates() {
            let current = self
                .accounts
                .get(&account_id)
                .map(|account| account.commitment)
                .or(store)
                .unwrap_or_default();

            if from != current {
                return Err(StateConflict::AccountCommitmentMismatch {
                    account: account_id,
                    expected: from,
                    current,
                });
            }
        }

        Ok(())
    }

    /// Appends the node to the graph state.
    ///
    /// This method assumes that the node is valid and you **must** call [`validate_append`] prior
    /// to this function.
    fn apply_append(&mut self, node: &N) {
        let id = node.id();

        self.children.entry(id).or_default();
        let mut parents = self.parents.entry(id).or_default();

        self.nullifiers.extend(node.nullifiers());
        self.notes_created.extend(node.output_notes().map(|note| (note, id)));

        parents.extend(
            node.unauthenticated_notes()
                .map(|note| self.notes_created.get(&note).expect("unauthenticated note must exist"))
                .copied(),
        );

        for (account, from, to, store) in node.account_updates() {
            // Create the account if it does not yet exist. Initialization should take the latest
            // store state (or ZERO).
            let mut account = self
                .accounts
                .entry(account)
                .or_insert_with(|| AccountState::new(store.unwrap_or_default()));

            // The owner of the current state is always a parent.
            parents.extend(account.owner);

            if from == to {
                account.pass_through.insert(id);
            } else {
                parents.extend(&account.pass_through);
                *account = AccountState::new(to);
                account.owner = Some(id);
            }
        }

        // Register this node as a child of all parents.
        for parent in parents.iter() {
            self.children
                .get_mut(parent)
                .expect("parent nodes should have a children entry")
                .insert(id);
        }
    }

    /// Returns the set of nodes which can be selected.
    ///
    /// These are nodes which have not been selected before, and who's parents have all been
    /// selected.
    pub fn selection_candidates(&self) -> HashSet<N::Id> {
        self.parents
            .iter()
            .filter(|(id, _)| !self.selected.contains(id))
            .filter(|(_, parents)| parents.iter().all(|parent| self.selected.contains(parent)))
            .map(|(&id, _)| id)
            .collect()
    }

    /// Returns `true` if the given node was previously selected.
    pub fn is_selected(&self, node: &N::Id) -> bool {
        self.selected.contains(node)
    }

    /// Marks a node as selected.
    ///
    /// # Panics
    ///
    /// Panics if the given node is not a selection candidate.
    pub fn select_candidate(&mut self, node: N::Id) {
        assert!(!self.selected.contains(&node));
        assert!(
            self.parents
                .get(&node)
                .unwrap()
                .iter()
                .all(|parent| self.selected.contains(parent))
        );

        self.selected.insert(node);
    }

    /// Returns the node's descendents.
    ///
    /// That is, this returns the node's children, their children etc.
    pub fn descendents(&self, node: &N::Id) -> HashSet<N::Id> {
        let mut to_process = vec![*node];
        let mut descendents = HashSet::default();

        while let Some(node) = to_process.pop() {
            let children = self.children.get(&node).unwrap();
            // Don't double process.
            to_process.extend(children.iter().filter(|child| !descendents.contains(*child)));
            descendents.extend(children);
        }

        descendents
    }

    /// Removes the node _IFF_ it is a leaf node (has no descendents).
    pub fn revert_leaf(&self, node: &N::Id) -> Option<N::Id> {
        todo!();
    }

    /// Removes the node _IFF_ it has no ancestor nodes.
    ///
    /// # Panics
    ///
    /// Panics if this node has any ancestor nodes.
    pub fn prune(&mut self, node: &N) {
        let id = node.id();
        assert!(
            self.parents.get(&id).unwrap().is_empty(),
            "Cannot prune node {id} as it still has ancestors",
        );

        self.remove(node);
    }

    /// Unconditionally removes the given node from the graph, deleting its edges and state.
    ///
    /// This is an _internal_ helper, caller is responsible for ensuring that the graph won't be
    /// corrupted by this removal. This is true if the node has either no parents, or no children.
    fn remove(&mut self, node: &N) {
        let id = node.id();

        // We destructure here so that we are reminded to clean up fields that get added in the
        // future.
        let Self {
            children,
            parents,
            selected,
            nullifiers,
            notes_created,
            accounts,
        } = self;

        // Remove edges.
        parents.remove(&id);
        let node_children = children.remove(&id).unwrap();
        for child in node_children {
            parents.get_mut(&child).unwrap().remove(&id);
        }

        // Remove state.
        for nullifier in node.nullifiers() {
            nullifiers.remove(&nullifier);
        }

        for note in node.output_notes() {
            notes_created.remove(&note);
        }

        for (account, ..) in node.account_updates() {
            let mut account = accounts.get_mut(&account).unwrap();
            account.owner.take_if(|owner| owner == &id);
            account.pass_through.remove(&id);
        }

        selected.remove(&id);
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateConflict {
    #[error("nullifiers already exist in the mempool: {0:?}")]
    NullifiersAlreadyExist(Vec<Nullifier>),
    #[error("output note commitments already exist in the mempool: {0:?}")]
    OutputNotesAlreadyExist(Vec<Word>),
    #[error("unauthenticated input notes are unknown: {0:?}")]
    UnauthenticatedNotesMissing(Vec<Word>),
    #[error(
        "node's initial account commitment {expected} does not match the current graph commitment {current} for account {account}"
    )]
    AccountCommitmentMismatch {
        account: AccountId,
        expected: Word,
        current: Word,
    },
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
    fn new(commitment: Word) -> Self {
        Self {
            commitment,
            owner: None,
            pass_through: HashSet::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.pass_through.is_empty()
    }
}
