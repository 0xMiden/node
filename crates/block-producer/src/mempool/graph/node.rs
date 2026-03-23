use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

/// Defines a node in the mempool graph.
pub trait GraphNode {
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

    /// The block height at which this node is considered expired.
    fn expires_at(&self) -> BlockNumber;
}

#[cfg(test)]
pub(crate) mod test_node {
    use miden_protocol::{Felt, FieldElement};

    use super::*;

    /// Lightweight [`GraphNode`] implementation for unit tests.
    #[derive(Clone, Debug)]
    pub struct TestNode {
        pub id: u32,
        pub nullifiers: Vec<Nullifier>,
        pub output_notes: Vec<Word>,
        pub unauthenticated_notes: Vec<Word>,
        pub account_updates: Vec<(AccountId, Word, Word, Option<Word>)>,
        pub expires_at: BlockNumber,
    }

    impl TestNode {
        pub fn new(id: u32) -> Self {
            Self {
                id,
                nullifiers: Vec::new(),
                output_notes: Vec::new(),
                unauthenticated_notes: Vec::new(),
                account_updates: Vec::new(),
                expires_at: BlockNumber::MAX,
            }
        }

        pub fn with_nullifiers(mut self, nullifiers: impl IntoIterator<Item = u32>) -> Self {
            self.nullifiers = nullifiers.into_iter().map(Self::to_nullifier).collect();
            self
        }

        pub fn with_output_notes(mut self, notes: impl IntoIterator<Item = u32>) -> Self {
            self.output_notes = notes.into_iter().map(Self::to_word).collect();
            self
        }

        pub fn with_unauthenticated_notes(mut self, notes: impl IntoIterator<Item = u32>) -> Self {
            self.unauthenticated_notes = notes.into_iter().map(Self::to_word).collect();
            self
        }

        pub fn with_account_update(mut self, update: (AccountId, u32, u32, Option<u32>)) -> Self {
            let (account, from, to, store) = update;
            self.account_updates.push((
                account,
                Self::to_word(from),
                Self::to_word(to),
                store.map(Self::to_word),
            ));
            self
        }

        pub fn with_expires_at(mut self, expires_at: BlockNumber) -> Self {
            self.expires_at = expires_at;
            self
        }

        fn to_word(value: u32) -> Word {
            Word::from([Felt::from(value), Felt::ZERO, Felt::ZERO, Felt::ZERO])
        }

        fn to_nullifier(value: u32) -> Nullifier {
            Nullifier::from_raw(Self::to_word(value))
        }
    }

    impl Default for TestNode {
        fn default() -> Self {
            Self::new(0)
        }
    }

    impl GraphNode for TestNode {
        type Id = u32;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
            Box::new(self.nullifiers.iter().copied())
        }

        fn output_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
            Box::new(self.output_notes.iter().copied())
        }

        fn unauthenticated_notes(&self) -> Box<dyn Iterator<Item = Word> + '_> {
            Box::new(self.unauthenticated_notes.iter().copied())
        }

        fn account_updates(
            &self,
        ) -> Box<dyn Iterator<Item = (AccountId, Word, Word, Option<Word>)> + '_> {
            Box::new(self.account_updates.iter().copied())
        }

        fn expires_at(&self) -> BlockNumber {
            self.expires_at
        }
    }
}
