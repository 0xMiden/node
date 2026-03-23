use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Maintains parent and child relationships between nodes in the mempool graph.
///
/// `Edges` tracks both sides of the relationship to support efficient queries for a node's
/// parents (dependencies) and children (dependants) while keeping the two maps in sync.
#[derive(Clone, Debug, PartialEq)]
pub struct Edges<Id>
where
    Id: Eq + Hash + Copy,
{
    parents: HashMap<Id, HashSet<Id>>,
    children: HashMap<Id, HashSet<Id>>,
}

impl<Id> Default for Edges<Id>
where
    Id: Eq + Hash + Copy,
{
    fn default() -> Self {
        Self {
            parents: HashMap::default(),
            children: HashMap::default(),
        }
    }
}

impl<Id> Edges<Id>
where
    Id: Eq + Hash + Copy,
{
    /// Registers a newly appended node's edges in the graph.
    ///
    /// Since it is newly appended, the node itself will only have parents and no children.
    /// The inverse child relationships are updated accordingly.
    ///
    /// # Panics
    ///
    /// Panics if the node is already tracked, or the parent nodes are not tracked.
    pub fn insert(&mut self, node: Id, parents: HashSet<Id>) {
        assert!(!self.children.contains_key(&node));

        self.parents.insert(node, parents.clone());
        self.children.insert(node, HashSet::default());

        for parent in parents {
            self.children.get_mut(&parent).unwrap().insert(node);
        }
    }

    /// Returns the parents of `node`.
    ///
    /// # Panics
    ///
    /// Panics if the node is not tracked.
    pub fn parents_of(&self, node: &Id) -> &HashSet<Id> {
        self.parents.get(node).unwrap()
    }

    /// Returns the children of `node`.
    ///
    /// # Panics
    ///
    /// Panics if the node is not tracked.
    pub fn children_of(&self, node: &Id) -> &HashSet<Id> {
        self.children.get(node).unwrap()
    }

    /// Removes the node from the edge set, updating all inverse relationships.
    ///
    /// # Panics
    ///
    /// Panics if the node is not tracked.
    pub fn remove(&mut self, node: &Id) {
        let parents = self.parents.remove(node).expect("node must exist when removing from edges");

        for parent in parents {
            if let Some(children) = self.children.get_mut(&parent) {
                children.remove(node);
            }
        }

        let children =
            self.children.remove(node).expect("node must exist when removing from edges");

        for child in children {
            if let Some(parents) = self.parents.get_mut(&child) {
                parents.remove(node);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::Edges;

    #[test]
    fn insert_adds_parent_child_relationships() {
        let mut edges = Edges::<u32>::default();

        edges.insert(1, HashSet::new());
        assert!(edges.parents_of(&1).is_empty());
        assert!(edges.children_of(&1).is_empty());

        edges.insert(2, HashSet::from([1]));

        assert_eq!(edges.parents_of(&2), &HashSet::from([1]));
        assert_eq!(edges.children_of(&1), &HashSet::from([2]));
        assert!(edges.children_of(&2).is_empty());
    }

    #[test]
    fn remove_updates_inverse_relationships() {
        let mut edges = Edges::<u32>::default();

        edges.insert(1, HashSet::new());
        edges.insert(2, HashSet::from([1]));
        edges.insert(3, HashSet::from([2]));

        edges.remove(&2);

        assert!(edges.children_of(&1).is_empty());
        assert!(edges.parents_of(&3).is_empty());

        edges.insert(4, HashSet::from([3]));

        assert_eq!(edges.parents_of(&4), &HashSet::from([3]));
        assert_eq!(edges.children_of(&3), &HashSet::from([4]));
    }
}
