use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::Hash;

use miden_protocol::block::BlockNumber;

use crate::mempool::StateConflict;
use crate::mempool::graph::edges::Edges;
use crate::mempool::graph::node::GraphNode;
use crate::mempool::graph::state::State;

#[derive(Clone, Debug, PartialEq)]
pub struct Graph<N>
where
    N: GraphNode,
    N::Id: Eq + Hash + Copy,
{
    /// All nodes present in the graph.
    nodes: HashMap<N::Id, N>,
    /// The aggregate state of all nodes in the graph.
    state: State<N::Id>,
    /// The relation between the nodes formed by their dependencies on each others state.
    edges: Edges<N::Id>,
    /// Nodes that have been selected.
    selected: HashSet<N::Id>,
    /// Nodes that are available for selection.
    ///
    /// These are nodes whose parents have all been selected.
    selection_candidates: BTreeSet<N::Id>,
}

impl<N> Default for Graph<N>
where
    N: GraphNode,
    N::Id: Eq + Hash + Copy,
{
    fn default() -> Self {
        Self {
            nodes: HashMap::default(),
            edges: Edges::default(),
            selected: HashSet::default(),
            selection_candidates: BTreeSet::default(),
            state: State::default(),
        }
    }
}

impl<N> Graph<N>
where
    N: GraphNode,
    N::Id: Eq + Hash + Copy + std::fmt::Display + Ord,
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
    pub fn append(&mut self, node: N) -> Result<(), StateConflict> {
        self.state.validate_append(&node)?;

        let id = node.id();
        let parents = self.state.apply_append(id, &node);
        self.edges.insert(id, parents);
        self.nodes.insert(id, node);
        self.selection_check(id);

        Ok(())
    }

    /// Returns the set of nodes which can be selected.
    ///
    /// Candidates are nodes that are not currently selected, have all parents selected, and can be
    /// handed directly to [`select_candidate`](Self::select_candidate).
    pub fn selection_candidates(&self) -> BTreeMap<&N::Id, &N> {
        self.selection_candidates
            .iter()
            .map(|id| (id, self.nodes.get(id).expect("selection_candidates is a subset of nodes")))
            .collect()
    }

    /// Returns `true` if the given node was previously selected.
    fn is_selected(&self, node: &N::Id) -> bool {
        self.selected.contains(node)
    }

    /// Marks the node as a selection candidate if all its parents are already selected.
    fn selection_check(&mut self, id: N::Id) {
        let parents = self.edges.parents_of(&id);
        if parents.iter().all(|parent| self.is_selected(parent)) {
            self.selection_candidates.insert(id);
        }
    }

    /// Marks the given node as unselected.
    ///
    /// # Panics
    ///
    /// Panics if the node was not previously selected or if any of its children are marked as
    /// selected.
    pub fn deselect(&mut self, node: N::Id) {
        assert!(
            self.is_selected(&node),
            "Cannot deselect node {node} which is not in selected set"
        );

        let children = self.edges.children_of(&node);
        assert!(
            children.iter().all(|child| !self.is_selected(child)),
            "Cannot deselect node {node} which still has children selected",
        );

        self.selected.remove(&node);
        // This makes the node a selection candidate by definition, and all its children should be
        // removed as candidates.
        self.selection_candidates.insert(node);
        for child in self.edges.children_of(&node) {
            self.selection_candidates.remove(child);
        }
    }

    /// Marks a node as selected.
    ///
    /// # Panics
    ///
    /// Panics if the given node is not a selection candidate.
    pub fn select_candidate(&mut self, node: N::Id) {
        assert!(!self.selected.contains(&node));
        assert!(self.edges.parents_of(&node).iter().all(|parent| self.selected.contains(parent)));

        self.selected.insert(node);
        self.selection_candidates.remove(&node);

        // Its children are now potential new candidates.
        let children = self.edges.children_of(&node).clone();
        for child in children {
            self.selection_check(child);
        }
    }

    /// Returns the node and its descendants.
    ///
    /// That is, this returns the node's children, their children etc.
    fn descendants(&self, node: &N::Id) -> HashSet<N::Id> {
        let mut to_process = vec![*node];
        let mut descendants = HashSet::default();

        while let Some(node) = to_process.pop() {
            // Don't double process.
            if descendants.contains(&node) {
                continue;
            }
            let children = self.edges.children_of(&node);
            to_process.extend(children);
            descendants.insert(node);
        }

        descendants
    }

    /// Reverts the given node and all of its descendants, returning the reverted nodes.
    ///
    /// Nodes are reverted from leaves (nodes without children) backwards, and are returned in
    /// that order. This is sort of a reverse chronological order i.e. this could be
    /// reversed and re-inserted without error.
    ///
    /// # Panics
    ///
    /// Panics if the node does not exist or if the graph invariants (such as acyclicity) are
    /// violated while unwinding descendants. The latter indicates graph corruption.
    pub fn revert_node_and_descendants(&mut self, id: N::Id) -> Vec<N> {
        let mut descendants = self.descendants(&id);

        // This implementation is O(n^2) and could be improved by tracking the chronological order
        // in which nodes are appended to the graph. This would let us revert in
        // reverse-chronological order which _must_ succeed by definition.
        //
        // However that is quite a bit more code, and won't be worth doing for quite some time.
        let mut reverted = Vec::new();
        'outer: while !descendants.is_empty() {
            for id in descendants.iter().copied() {
                if self.is_leaf(&id) {
                    reverted.push(self.remove(id));
                    descendants.remove(&id);
                    continue 'outer;
                }
            }

            panic!("failed to make progress");
        }

        reverted
    }

    /// Nodes which are expired and should be reverted.
    ///
    /// Only nodes which are **not selected** are returned since selected nodes are assumed to be
    /// committed.
    pub fn expired_and_unselected(&self, chain_tip: BlockNumber) -> HashSet<N::Id> {
        self.nodes
            .iter()
            .filter(|(id, _)| !self.is_selected(id))
            .filter_map(|(id, node)| (node.expires_at() <= chain_tip).then_some(id))
            .copied()
            .collect()
    }

    /// Returns `true` if the given node is a leaf node aka has no children.
    fn is_leaf(&self, id: &N::Id) -> bool {
        self.edges.children_of(id).is_empty()
    }

    /// Removes the node _IFF_ it has no ancestor nodes.
    ///
    /// # Panics
    ///
    /// Panics if this node has any ancestor nodes, or if this node was not selected.
    pub fn prune(&mut self, id: N::Id) {
        assert!(
            self.edges.parents_of(&id).is_empty(),
            "Cannot prune node {id} as it still has ancestors",
        );
        assert!(self.selected.contains(&id), "Cannot prune node {id} as it was not selected");

        self.remove(id);
    }

    /// Unconditionally removes the given node from the graph, deleting its edges and state.
    ///
    /// This is an _internal_ helper, caller is responsible for ensuring that the graph won't be
    /// corrupted by this removal. This is true if the node has no parents, or no children.
    fn remove(&mut self, id: N::Id) -> N {
        // Destructure so we are reminded to clean up new fields.
        let Self {
            nodes,
            state,
            edges,
            selected,
            selection_candidates,
        } = self;

        let node = nodes.remove(&id).unwrap();
        state.remove(&node);
        selected.remove(&id);
        edges.remove(&id);
        selection_candidates.remove(&id);

        node
    }

    pub fn selected_count(&self) -> usize {
        self.selected.len()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn account_count(&self) -> usize {
        self.state.account_count()
    }

    pub fn nullifier_count(&self) -> usize {
        self.state.nullifier_count()
    }

    pub fn output_note_count(&self) -> usize {
        self.state.output_note_count()
    }

    pub fn contains(&self, node: &N::Id) -> bool {
        self.nodes.contains_key(node)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use miden_protocol::block::BlockNumber;

    use super::*;
    use crate::mempool::graph::node::test_node::TestNode;

    #[test]
    fn child_becomes_candidate_after_parent_selection() {
        let mut graph = Graph::<TestNode>::default();

        graph
            .append(
                TestNode::new(1)
                    .with_output_notes([1])
                    .with_expires_at(BlockNumber::from(10u32)),
            )
            .unwrap();
        graph
            .append(
                TestNode::new(2)
                    .with_output_notes([2])
                    .with_unauthenticated_notes([1])
                    .with_expires_at(BlockNumber::from(10u32)),
            )
            .unwrap();

        let initial_candidates: Vec<u32> =
            graph.selection_candidates().keys().map(|id| **id).collect();
        assert_eq!(initial_candidates, vec![1]);

        graph.select_candidate(1);

        let candidates_after_parent: Vec<u32> =
            graph.selection_candidates().keys().map(|id| **id).collect();
        assert_eq!(candidates_after_parent, vec![2]);
    }

    #[test]
    fn expired_and_unselected_returns_only_expired_unselected_nodes() {
        let mut graph = Graph::<TestNode>::default();

        graph
            .append(
                TestNode::new(1).with_output_notes([1]).with_expires_at(BlockNumber::from(5u32)),
            )
            .unwrap();
        graph
            .append(
                TestNode::new(2).with_output_notes([2]).with_expires_at(BlockNumber::from(6u32)),
            )
            .unwrap();
        graph
            .append(
                TestNode::new(3)
                    .with_output_notes([3])
                    .with_expires_at(BlockNumber::from(10u32)),
            )
            .unwrap();

        graph.select_candidate(1);

        let expired = graph.expired_and_unselected(BlockNumber::from(6u32));
        let mut expected = HashSet::new();
        expected.insert(2u32);

        assert_eq!(expired, expected);
    }
}
