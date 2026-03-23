use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::hash::Hash;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::Nullifier;

use crate::errors::StateConflict;
use crate::mempool::graph::node::GraphNode;

/// Tracks the shared state of the mempool graph that is required to validate and apply nodes.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct State<K>
where
    K: Eq + Hash + Copy,
{
    nullifiers: HashSet<Nullifier>,
    notes_created: HashMap<Word, K>,
    accounts: HashMap<AccountId, AccountStates<K>>,
}

impl<K> Default for State<K>
where
    K: Eq + Hash + Copy,
{
    fn default() -> Self {
        Self {
            nullifiers: HashSet::default(),
            notes_created: HashMap::default(),
            accounts: HashMap::default(),
        }
    }
}

impl<K> State<K>
where
    K: Eq + Hash + Copy,
{
    /// Ensures that `node` can be appended on top of the current state without conflicts.
    pub(super) fn validate_append<N>(&self, node: &N) -> Result<(), StateConflict>
    where
        N: GraphNode<Id = K>,
    {
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

        for (account_id, from, _to, store) in node.account_updates() {
            let current = self
                .accounts
                .get(&account_id)
                .map(AccountStates::commitment)
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

    /// Applies `node` to the state, returning the set of parent node identifiers inferred from
    /// state dependencies.
    pub(super) fn apply_append<N>(&mut self, node_id: K, node: &N) -> HashSet<K>
    where
        N: GraphNode<Id = K>,
    {
        let mut parents = HashSet::new();

        self.nullifiers.extend(node.nullifiers());
        self.notes_created.extend(node.output_notes().map(|note| (note, node_id)));

        parents.extend(node.unauthenticated_notes().map(|note| {
            *self
                .notes_created
                .get(&note)
                .expect("unauthenticated note must exist in the state")
        }));

        for (account_id, from, to, store) in node.account_updates() {
            let account = self
                .accounts
                .entry(account_id)
                .or_insert_with(|| AccountStates::new(store.unwrap_or_default()));

            if let Some(owner) = account.current_owner() {
                parents.insert(owner);
            }

            if from == to {
                account.insert_pass_through(node_id);
            } else {
                let passthrough_parents: Vec<_> = account.current_pass_through().collect();
                parents.extend(passthrough_parents);
                account.append_state(to, node_id);
            }
        }

        parents
    }

    /// Removes all state associated with `node`, undoing the effects of [`Self::apply_append`].
    pub(super) fn remove<N>(&mut self, node: &N)
    where
        N: GraphNode<Id = K>,
        N::Id: Display,
    {
        let node_id = node.id();

        for nullifier in node.nullifiers() {
            self.nullifiers.remove(&nullifier);
        }

        for note in node.output_notes() {
            self.notes_created.remove(&note);
        }

        for (account_id, from, to, ..) in node.account_updates() {
            let Entry::Occupied(mut account_entry) = self.accounts.entry(account_id) else {
                panic!(
                    "Cannot remove account {account_id} entry for node {node_id} as it does not exist"
                );
            };

            account_entry.get_mut().remove_node(&node_id, from, to);

            if account_entry.get().is_empty() {
                account_entry.remove();
            }
        }
    }
}

/// Tracks the per-account state transitions that are in-flight within the mempool graph.
#[derive(Clone, Debug, PartialEq)]
struct AccountStates<K>
where
    K: Eq + Hash + Copy,
{
    commitment: Word,
    nodes: HashMap<Word, CommitmentNodes<K>>,
}

impl<K> AccountStates<K>
where
    K: Eq + Hash + Copy,
{
    fn new(commitment: Word) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(commitment, CommitmentNodes::default());

        Self { commitment, nodes }
    }

    fn append_state(&mut self, commitment: Word, owner: K) {
        self.commitment = commitment;
        self.nodes.insert(commitment, CommitmentNodes::with_owner(owner));
    }

    fn remove_node(&mut self, node: &K, from: Word, to: Word) {
        let Entry::Occupied(mut entry) = self.nodes.entry(to) else {
            panic!("Account node could not be removed because its commitment does not exist");
        };

        entry.get_mut().remove(node);

        if entry.get().is_empty() {
            entry.remove();

            if self.commitment == to {
                self.commitment = from;
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn current_owner(&self) -> Option<K> {
        self.current_nodes().owner
    }

    fn current_pass_through(&self) -> impl Iterator<Item = K> + '_ {
        self.current_nodes().pass_through.iter().copied()
    }

    fn insert_pass_through(&mut self, node: K) {
        self.current_nodes_mut().pass_through.insert(node);
    }

    fn commitment(&self) -> Word {
        self.commitment
    }

    fn current_nodes(&self) -> &CommitmentNodes<K> {
        self.nodes.get(&self.commitment).expect("current commitment must exist")
    }

    fn current_nodes_mut(&mut self) -> &mut CommitmentNodes<K> {
        self.nodes.get_mut(&self.commitment).expect("current commitment must exist")
    }
}

/// Associates node identifiers with a single account commitment.
#[derive(Clone, Debug, PartialEq)]
struct CommitmentNodes<K>
where
    K: Eq + Hash + Copy,
{
    owner: Option<K>,
    pass_through: HashSet<K>,
}

impl<K> Default for CommitmentNodes<K>
where
    K: Eq + Hash + Copy,
{
    fn default() -> Self {
        Self {
            owner: None,
            pass_through: HashSet::default(),
        }
    }
}

impl<K> CommitmentNodes<K>
where
    K: Eq + Hash + Copy,
{
    fn with_owner(owner: K) -> Self {
        Self {
            owner: Some(owner),
            pass_through: HashSet::default(),
        }
    }

    fn remove(&mut self, node: &K) {
        if self.owner.as_ref() == Some(node) {
            self.owner = None;
        }
        self.pass_through.remove(node);
    }

    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.pass_through.is_empty()
    }
}
