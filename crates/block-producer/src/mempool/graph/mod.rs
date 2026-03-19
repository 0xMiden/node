use std::collections::HashSet;
use std::hash::Hash;

mod batch;
mod edges;
mod state;
mod transaction;

pub use batch::BatchGraph;
use edges::Edges;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::Nullifier;
use state::State;
pub use state::StateConflict;
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
    N::Id: Eq + std::hash::Hash + Copy,
{
    /// The aggregate state of all nodes in the graph.
    state: State<N::Id>,
    /// The relation between the nodes formed by their dependencies on each others state.
    edges: Edges<N::Id>,
    /// Nodes that have been selected. Nodes are available for selection once _all_ their parents
    /// have been selected.
    selected: HashSet<N::Id>,
}

impl<N> Default for Graph<N>
where
    N: GraphNode,
    N::Id: Eq + std::hash::Hash + Copy,
{
    fn default() -> Self {
        Self {
            edges: Edges::default(),
            selected: HashSet::default(),
            state: State::default(),
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
        self.state.validate_append(node)?;

        let id = node.id();
        let parents = self.state.apply_append(id, node);
        self.edges.insert(id, parents);

        Ok(())
    }

    /// Returns the set of nodes which can be selected.
    ///
    /// These are nodes which have not been selected before, and who's parents have all been
    /// selected.
    pub fn selection_candidates(&self) -> HashSet<N::Id> {
        self.edges
            .iter()
            .filter(|(id, _)| !self.selected.contains(id))
            .filter(|(_, parents)| parents.iter().all(|parent| self.selected.contains(parent)))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns `true` if the given node was previously selected.
    pub fn is_selected(&self, node: &N::Id) -> bool {
        self.selected.contains(node)
    }

    /// Marks the given node as unselected.
    ///
    /// # Panics
    ///
    /// Panics if the node was not previously selected or if any of its children are marked as
    /// selected.
    pub fn deselect(&mut self, node: &N::Id) {
        assert!(
            self.is_selected(node),
            "Cannot deselect node {node} which is not in selected set"
        );

        let children = self.edges.children_of(node);
        assert!(
            children.iter().all(|child| !self.is_selected(child)),
            "Cannot deselect node {node} which still has children selected",
        );

        self.selected.remove(node);
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
    }

    /// Returns the node and its descendents.
    ///
    /// That is, this returns the node's children, their children etc.
    pub fn descendents(&self, node: &N::Id) -> HashSet<N::Id> {
        let mut to_process = vec![*node];
        let mut descendents = HashSet::default();

        while let Some(node) = to_process.pop() {
            // Don't double process.
            if descendents.contains(&node) {
                continue;
            }
            let children = self.edges.children_of(&node);
            to_process.extend(children);
            descendents.insert(node);
        }

        descendents
    }

    /// Returns `true` if the given node is a leaf node aka has no children.
    pub fn is_leaf(&self, node: &N::Id) -> bool {
        self.edges.children_of(node).is_empty()
    }

    /// Removes the leaf node from the graph.
    ///
    /// # Panics
    ///
    /// Panics if the node **is not** a leaf node. Use [`is_leaf`] to ensure it is.
    pub fn revert_leaf(&mut self, node: &N) {
        let id = node.id();
        assert!(self.is_leaf(&id), "Cannot revert node {id} as it still has descendents",);

        self.remove(node);
    }

    /// Removes the node _IFF_ it has no ancestor nodes.
    ///
    /// # Panics
    ///
    /// Panics if this node has any ancestor nodes.
    pub fn prune(&mut self, node: &N) {
        let id = node.id();
        assert!(
            self.edges.parents_of(&id).is_empty(),
            "Cannot prune node {id} as it still has ancestors",
        );

        self.remove(node);
    }

    /// Unconditionally removes the given node from the graph, deleting its edges and state.
    ///
    /// This is an _internal_ helper, caller is responsible for ensuring that the graph won't be
    /// corrupted by this removal. This is true if the node has either no parents, or no children.
    fn remove(&mut self, node: &N) {
        self.state.remove(node);
        self.selected.remove(&node.id());
        self.edges.remove(&node.id());
    }

    pub fn selected_count(&self) -> usize {
        self.selected.len()
    }
}
