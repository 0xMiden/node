//! Utilities for tracking per-account state transitions inside the mempool graph.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use miden_protocol::Word;

/// Tracks the in-flight state transitions for a single account within the mempool graph.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountStates<K>
where
    K: Eq + Hash,
{
    /// The latest account state commitment.
    commitment: Word,
    /// Mapping of commitment to the nodes of that commitment.
    ///
    /// This contains all tracked commitments and their associated nodes.
    nodes: HashMap<Word, CommitmentNodes<K>>,
}

/// The set of nodes that are associated with a specific account commitment.
#[derive(Clone, Debug, PartialEq)]
struct CommitmentNodes<K>
where
    K: Eq + Hash,
{
    /// The node that caused the transition **to** the commitment.
    owner: Option<K>,
    /// Pass through nodes aka nodes where both _to_ **and** _from_ are the commitment.
    pass_through: HashSet<K>,
}

impl<K> AccountStates<K>
where
    K: Eq + Hash,
{
    /// Creates an account state with the given commitment and no nodes registered.
    pub fn empty(commitment: Word) -> Self {
        Self {
            commitment,
            nodes: HashMap::from([(commitment, CommitmentNodes::empty())]),
        }
    }

    /// Records a new commitment produced by a node.
    pub fn append_state(&mut self, commitment: Word, owner: K) {
        self.commitment = commitment;
        self.nodes.insert(commitment, CommitmentNodes::with_owner(owner));
    }

    /// Removes the provided node from the tracked commitment history, rolling back if needed.
    pub fn remove_node(&mut self, node: &K, from: Word, to: Word) {
        let Entry::Occupied(mut nodes) = self.nodes.entry(to) else {
            panic!("Account node could not be removed because its commitment does not exist");
        };

        nodes.get_mut().remove(node);
        if nodes.get().is_empty() {
            nodes.remove();
        }

        // If we just removed the latest tracked commitment, then update it to the node's initial
        // commitment.
        //
        // Note that this is also the correct behavior for pass through nodes -- since in that case
        // `from == to` and therefore `self.commitment` remains unchanged.
        if self.commitment == to {
            self.commitment = from;
        }
    }

    /// Returns `true` when no commitments are being tracked for the account.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the node that currently owns the latest commitment, if any.
    pub fn current_owner(&self) -> Option<&K> {
        self.current_nodes().owner.as_ref()
    }

    /// Returns the set of nodes that are pass through of the latest commitment.
    /// it.
    pub fn current_pass_through(&self) -> &HashSet<K> {
        &self.current_nodes().pass_through
    }

    /// Registers a pass through node at the current commitment.
    pub fn insert_pass_through(&mut self, node: K) {
        self.current_nodes_mut().pass_through.insert(node);
    }

    /// Returns the current commitment tracked for the account.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    fn current_nodes(&self) -> &CommitmentNodes<K> {
        self.nodes.get(&self.commitment).as_ref().unwrap()
    }

    fn current_nodes_mut(&mut self) -> &mut CommitmentNodes<K> {
        self.nodes.get_mut(&self.commitment).unwrap()
    }
}

impl<K> CommitmentNodes<K>
where
    K: Eq + Hash,
{
    fn with_owner(owner: K) -> Self {
        let mut this = Self::empty();
        this.owner = Some(owner);
        this
    }

    /// Creates an empty node set.
    fn empty() -> Self {
        Self {
            owner: None,
            pass_through: HashSet::default(),
        }
    }

    /// Removes the node from the set.
    fn remove(&mut self, node: &K) {
        self.owner.take_if(|owner| owner == node);
        self.pass_through.remove(node);
    }

    /// Returns `true` if there is no tracked node in the set
    ///
    /// aka there is no owner, and no pass through nodes.
    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.pass_through.is_empty()
    }
}
