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
