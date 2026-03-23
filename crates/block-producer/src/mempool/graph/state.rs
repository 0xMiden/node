use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
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

        for (account_id, from, to, _store) in node.account_updates() {
            let account = self.accounts.entry(account_id);

            if from == to {
                account
                    .and_modify(|account| {
                        parents.extend(account.current_owner());
                        account.insert_pass_through(node_id);
                    })
                    .or_insert_with(|| AccountStates::with_pass_through(to, node_id))
            } else {
                account
                    .and_modify(|account| {
                        parents.extend(account.current_owner());
                        parents.extend(account.current_pass_through());
                        account.append_state(to, node_id);
                    })
                    .or_insert_with(|| AccountStates::with_owner(to, node_id))
            };
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

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn output_note_count(&self) -> usize {
        self.notes_created.len()
    }
}

/// Tracks the per-account state transitions that are in-flight within the mempool graph.
#[derive(Clone, Debug, PartialEq)]
struct AccountStates<K>
where
    K: Eq + Hash + Copy,
{
    commitment: Word,
    nodes: VecDeque<CommitmentNodes<K>>,
}

impl<K> AccountStates<K>
where
    K: Eq + Hash + Copy,
{
    fn with_owner(commitment: Word, owner: K) -> Self {
        let nodes = CommitmentNodes::with_owner(owner);
        let nodes = VecDeque::from([nodes]);

        Self { commitment, nodes }
    }

    fn with_pass_through(commitment: Word, node: K) -> Self {
        let nodes = CommitmentNodes::with_pass_through(node);
        let nodes = VecDeque::from([nodes]);

        Self { commitment, nodes }
    }

    fn append_state(&mut self, commitment: Word, owner: K) {
        self.commitment = commitment;
        self.nodes.push_back(CommitmentNodes::with_owner(owner));
    }

    fn remove_node(&mut self, node: &K, from: Word, to: Word) {
        if to == self.commitment {
            let nodes = self.nodes.back_mut().unwrap();
            nodes.remove(node);

            if nodes.is_empty() {
                self.nodes.pop_back();
                self.commitment = from;
            }
        } else {
            let nodes = self.nodes.front_mut().unwrap();
            nodes.remove(node);

            if nodes.is_empty() {
                self.nodes.pop_front();
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
        self.nodes
            .back_mut()
            .expect("current commitment must exist")
            .pass_through
            .insert(node);
    }

    fn commitment(&self) -> Word {
        self.commitment
    }

    fn current_nodes(&self) -> &CommitmentNodes<K> {
        self.nodes.back().expect("current commitment must exist")
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

    fn with_pass_through(node: K) -> Self {
        Self {
            owner: None,
            pass_through: HashSet::from([node]),
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use miden_protocol::note::Nullifier;
    use miden_protocol::{Felt, FieldElement, Word};

    use super::*;
    use crate::errors::StateConflict;
    use crate::mempool::graph::node::test_node::TestNode;
    use crate::test_utils::mock_account_id;

    fn word(value: u32) -> Word {
        Word::from([Felt::from(value), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    fn nullifier(value: u32) -> Nullifier {
        Nullifier::from_raw(word(value))
    }

    #[test]
    fn validate_append_rejects_duplicate_nullifiers() {
        let mut state = State::<u32>::default();
        let account_id = mock_account_id(1);

        let node_a = TestNode::new(1)
            .with_nullifiers([1])
            .with_output_notes([11])
            .with_account_update((account_id, 0, 2, None));

        state.validate_append(&node_a).unwrap();
        state.apply_append(node_a.id, &node_a);

        let node_b = TestNode::new(2)
            .with_nullifiers([1])
            .with_output_notes([22])
            .with_unauthenticated_notes([11])
            .with_account_update((account_id, 2, 3, None));

        match state.validate_append(&node_b) {
            Err(StateConflict::NullifiersAlreadyExist(duplicates)) => {
                assert_eq!(duplicates, vec![nullifier(1)]);
            },
            other => panic!("expected duplicate nullifier error, found {other:?}"),
        }
    }

    #[test]
    fn apply_append_registers_parents_and_counts() {
        let mut state = State::<u32>::default();
        let account_id = mock_account_id(2);

        let node_a = TestNode::new(10)
            .with_nullifiers([10])
            .with_output_notes([42])
            .with_account_update((account_id, 0, 5, None));

        state.validate_append(&node_a).unwrap();
        state.apply_append(node_a.id, &node_a);

        let node_b = TestNode::new(11)
            .with_output_notes([43])
            .with_unauthenticated_notes([42])
            .with_account_update((account_id, 5, 6, None));

        state.validate_append(&node_b).unwrap();
        let parents = state.apply_append(node_b.id, &node_b);

        assert_eq!(parents, HashSet::from([node_a.id]));
        assert_eq!(state.account_count(), 1);
        assert_eq!(state.nullifier_count(), 1);
        assert_eq!(state.output_note_count(), 2);
    }

    #[test]
    fn validate_append_rejects_duplicate_output_notes() {
        let mut state = State::<u32>::default();
        let account_id = mock_account_id(4);

        let node_a = TestNode::new(30)
            .with_output_notes([200])
            .with_account_update((account_id, 0, 5, None));
        state.validate_append(&node_a).unwrap();
        state.apply_append(node_a.id, &node_a);

        let node_b = TestNode::new(31)
            .with_output_notes([200])
            .with_account_update((account_id, 5, 6, None));

        match state.validate_append(&node_b) {
            Err(StateConflict::OutputNotesAlreadyExist(duplicates)) => {
                assert_eq!(duplicates, vec![word(200)]);
            },
            other => panic!("expected duplicate output note error, found {other:?}"),
        }
    }

    #[test]
    fn validate_append_rejects_unknown_unauthenticated_notes() {
        let state = State::<u32>::default();
        let account_id = mock_account_id(5);

        let node = TestNode::new(40)
            .with_unauthenticated_notes([300])
            .with_account_update((account_id, 0, 0, None));

        match state.validate_append(&node) {
            Err(StateConflict::UnauthenticatedNotesMissing(missing)) => {
                assert_eq!(missing, vec![word(300)]);
            },
            other => panic!("expected missing unauthenticated note error, found {other:?}"),
        }
    }

    #[test]
    fn validate_append_rejects_account_commitment_mismatch() {
        let state = State::<u32>::default();
        let account_id = mock_account_id(6);

        let node = TestNode::new(50).with_account_update((account_id, 400, 401, None));

        match state.validate_append(&node) {
            Err(StateConflict::AccountCommitmentMismatch { expected, current, .. }) => {
                assert_eq!(expected, word(400));
                assert_eq!(current, Word::default());
            },
            other => panic!("expected account commitment mismatch error, found {other:?}"),
        }
    }

    #[test]
    fn remove_cleans_up_account_state() {
        let mut state = State::<u32>::default();
        let account_id = mock_account_id(3);

        let node_a = TestNode::new(21)
            .with_nullifiers([21])
            .with_output_notes([100])
            .with_account_update((account_id, 0, 7, None));
        state.validate_append(&node_a).unwrap();
        state.apply_append(node_a.id, &node_a);

        let node_b = TestNode::new(22)
            .with_output_notes([101])
            .with_account_update((account_id, 7, 8, None));
        state.validate_append(&node_b).unwrap();
        state.apply_append(node_b.id, &node_b);

        state.remove(&node_b);
        assert_eq!(state.nullifier_count(), 1);
        assert_eq!(state.output_note_count(), 1);
        assert_eq!(state.account_count(), 1);

        state.remove(&node_a);
        assert_eq!(state.nullifier_count(), 0);
        assert_eq!(state.output_note_count(), 0);
        assert_eq!(state.account_count(), 0);
    }
}
