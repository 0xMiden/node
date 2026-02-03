//! Historical tracking for `AccountTree` via mutation overlays

use std::collections::{BTreeMap, HashMap};

use miden_protocol::account::{AccountId, AccountIdPrefix};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::{AccountMutationSet, AccountTree, AccountWitness};
use miden_protocol::crypto::merkle::smt::{
    LargeSmt,
    LeafIndex,
    MemoryStorage,
    NodeMutation,
    SMT_DEPTH,
    SmtLeaf,
    SmtStorage,
};
use miden_protocol::crypto::merkle::{
    EmptySubtreeRoots,
    MerkleError,
    MerklePath,
    NodeIndex,
    SparseMerklePath,
};
use miden_protocol::errors::AccountTreeError;
use miden_protocol::{EMPTY_WORD, Word};

#[cfg(test)]
mod tests;

/// Convenience for an in-memory-only account tree.
pub type InMemoryAccountTree = AccountTree<LargeSmt<MemoryStorage>>;

#[cfg(feature = "rocksdb")]
/// Convenience for a persistent account tree.
pub type PersistentAccountTree = AccountTree<LargeSmt<miden_crypto::merkle::smt::RocksDbStorage>>;

// HISTORICAL ERROR TYPES
// ================================================================================================

#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
pub enum HistoricalError {
    #[error(transparent)]
    MerkleError(#[from] MerkleError),
    #[error(transparent)]
    AccountTreeError(#[from] AccountTreeError),
}

// HISTORICAL SELECTOR ENUM
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoricalSelector {
    /// The requested block is in the future (later than current block).
    Future,
    /// The requested block is available in history.
    At(BlockNumber),
    /// The requested block is the current/latest block.
    Latest,
    /// The requested block is too old and has been pruned from history.
    TooAncient,
}

// HISTORICAL OVERLAY
// ================================================================================================

/// Captures reversion state for historical queries at a specific block.
#[derive(Debug, Clone)]
struct HistoricalOverlay {
    block_number: BlockNumber,
    root: Word,
    node_mutations: HashMap<NodeIndex, Word>,
    account_updates: HashMap<LeafIndex<SMT_DEPTH>, (Word, Word)>,
}

impl HistoricalOverlay {
    fn new(block_number: BlockNumber, rev_set: AccountMutationSet) -> Self {
        let root = rev_set.as_mutation_set().root();
        let mut_set = rev_set.into_mutation_set();

        let node_mutations =
            HashMap::from_iter(mut_set.node_mutations().iter().map(|(node_index, mutation)| {
                match mutation {
                    NodeMutation::Addition(inner_node) => (*node_index, inner_node.hash()),
                    NodeMutation::Removal => {
                        // Store the actual empty subtree root for this depth
                        // depth() is 1-indexed from leaf, so we use it directly for
                        // EmptySubtreeRoots
                        let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, node_index.depth());
                        (*node_index, empty_root)
                    },
                }
            }));

        let account_updates = HashMap::from_iter(
            mut_set.new_pairs().iter().map(|(&k, &v)| (LeafIndex::from(k), (k, v))),
        );

        Self {
            block_number,
            root,
            node_mutations,
            account_updates,
        }
    }
}

// ACCOUNT TREE WITH HISTORY
// ================================================================================================

/// Wraps `AccountTree` with historical query support via reversion overlays.
///
/// This structure maintains a sliding window of historical account states by storing
/// reversion data (mutations that undo changes). Historical witnesses are reconstructed
/// by starting from the latest state and applying reversion overlays backwards in time.
#[derive(Debug)]
pub struct AccountTreeWithHistory<S: SmtStorage> {
    /// The current block number (latest state).
    block_number: BlockNumber,
    /// The latest account tree state.
    latest: AccountTree<LargeSmt<S>>,
    /// Historical overlays indexed by block number, storing reversion data.
    overlays: BTreeMap<BlockNumber, HistoricalOverlay>,
}

impl<S: SmtStorage> AccountTreeWithHistory<S> {
    /// Maximum number of historical blocks to maintain.
    pub const MAX_HISTORY: usize = 50;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new historical tree starting at the given block number.
    pub fn new(account_tree: AccountTree<LargeSmt<S>>, block_number: BlockNumber) -> Self {
        Self {
            block_number,
            latest: account_tree,
            overlays: BTreeMap::new(),
        }
    }

    /// Removes oldest overlays when exceeding the maximum history depth.
    fn drain_excess(overlays: &mut BTreeMap<BlockNumber, HistoricalOverlay>) {
        while overlays.len() > Self::MAX_HISTORY {
            overlays.pop_first();
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the latest block number.
    pub fn block_number_latest(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the root hash of the latest state.
    pub fn root_latest(&self) -> Word {
        self.latest.root()
    }

    /// Returns the root hash at a specific historical block.
    ///
    /// Returns `None` if the block is in the future or too old (pruned).
    pub fn root_at(&self, block_number: BlockNumber) -> Option<Word> {
        match self.historical_selector(block_number) {
            HistoricalSelector::Latest => Some(self.latest.root()),
            HistoricalSelector::At(block_number) => {
                let overlay = self.overlays.get(&block_number)?;
                debug_assert_eq!(overlay.block_number, block_number);
                Some(overlay.root)
            },
            HistoricalSelector::Future | HistoricalSelector::TooAncient => None,
        }
    }

    /// Returns the number of accounts in the latest state.
    pub fn num_accounts_latest(&self) -> usize {
        self.latest.num_accounts()
    }

    /// Returns the number of historical blocks currently stored.
    pub fn history_len(&self) -> usize {
        self.overlays.len()
    }

    /// Opens an account at the latest block, returning its witness.
    pub fn open_latest(&self, account_id: AccountId) -> AccountWitness {
        self.latest.open(account_id)
    }

    /// Opens an account at a historical block, returning its witness.
    ///
    /// This method reconstructs the account witness at the given historical block by:
    /// 1. Starting with the latest account state
    /// 2. Applying reversion mutations from the overlays to walk back in time
    /// 3. Reconstructing the Merkle path with the historical node values
    ///
    /// Returns `None` if the block is in the future or too old (pruned).
    pub fn open_at(
        &self,
        account_id: AccountId,
        block_number: BlockNumber,
    ) -> Option<AccountWitness> {
        match self.historical_selector(block_number) {
            HistoricalSelector::Latest => Some(self.latest.open(account_id)),
            HistoricalSelector::At(block_number) => {
                // Ensure overlay exists before reconstruction
                self.overlays.get(&block_number)?;
                Self::reconstruct_historical_witness(self, account_id, block_number)
            },
            HistoricalSelector::Future | HistoricalSelector::TooAncient => None,
        }
    }

    /// Gets the account state commitment at the latest block.
    pub fn get_latest_commitment(&self, account_id: AccountId) -> Word {
        self.latest.get(account_id)
    }

    /// Checks if the tree contains an account with the given prefix.
    pub fn contains_account_id_prefix_in_latest(&self, prefix: AccountIdPrefix) -> bool {
        self.latest.contains_account_id_prefix(prefix)
    }

    // PRIVATE HELPERS - HISTORICAL RECONSTRUCTION
    // --------------------------------------------------------------------------------------------

    /// Determines the historical state selector of a requested block number.
    fn historical_selector(&self, desired_block_number: BlockNumber) -> HistoricalSelector {
        if desired_block_number == self.block_number {
            return HistoricalSelector::Latest;
        }

        // Check if block is in the future
        if self.block_number.checked_sub(desired_block_number.as_u32()).is_none() {
            return HistoricalSelector::Future;
        }

        // Check if block exists in overlays
        if !self.overlays.contains_key(&desired_block_number) {
            return HistoricalSelector::TooAncient;
        }

        HistoricalSelector::At(desired_block_number)
    }

    /// Reconstructs a historical account witness by applying reversion overlays.
    fn reconstruct_historical_witness(
        &self,
        account_id: AccountId,
        block_target: BlockNumber,
    ) -> Option<AccountWitness> {
        // Start with the latest witness
        let latest_witness = self.latest.open(account_id);
        let (latest_path, leaf) = latest_witness.into_proof().into_parts();
        let path_nodes = Self::initialize_path_nodes(&latest_path);

        let leaf_index = NodeIndex::from(leaf.index());

        // Apply reversion overlays to reconstruct historical state.
        // We reverse the overlay iteration (newest to oldest) to walk backwards in time
        // from the latest state to the target block.
        let (path, leaf) = Self::apply_reversion_overlays(
            self.overlays.range(block_target..).rev().map(|(_, overlay)| overlay),
            path_nodes,
            leaf_index,
            leaf,
        )?;

        // Extract commitment from leaf
        let commitment = match leaf {
            SmtLeaf::Empty(_) => EMPTY_WORD,
            SmtLeaf::Single((_, value)) => value,
            SmtLeaf::Multiple(_) => unreachable!("AccountTree uses prefix-free IDs"),
        };

        AccountWitness::new(account_id, commitment, path).ok()
    }

    /// Initializes the path nodes array from the latest state.
    ///
    /// Converts the sparse path to a dense path and reverses it for indexing by depth from leaf.
    fn initialize_path_nodes(path: &SparseMerklePath) -> [Word; SMT_DEPTH as usize] {
        let mut path_nodes: [Word; SMT_DEPTH as usize] = MerklePath::from(path.clone())
            .to_vec()
            .try_into()
            .expect("MerklePath should have exactly SMT_DEPTH nodes");
        path_nodes.reverse();
        path_nodes
    }

    /// Applies reversion overlays to reconstruct the historical state.
    ///
    /// Iterates through overlays from newest to oldest (walking backwards in time),
    /// updating both the path nodes and the leaf value based on reversion mutations.
    fn apply_reversion_overlays<'a>(
        overlays: impl IntoIterator<Item = &'a HistoricalOverlay>,
        mut path_nodes: [Word; SMT_DEPTH as usize],
        leaf_index: NodeIndex,
        mut leaf: SmtLeaf,
    ) -> Option<(SparseMerklePath, SmtLeaf)> {
        // Iterate through overlays
        for overlay in overlays {
            // Update path sibling nodes that changed in this overlay
            for sibling in leaf_index.proof_indices() {
                let height = sibling
                    .depth()
                    .checked_sub(1) // -1: Convert from 1-indexed to 0-indexed
                    .expect("proof_indices should not include root")
                    as usize;

                // Apply reversion mutation if this node was modified.
                // It's sound since `proof_indices()`` returns siblings on the path from leaf to
                // root, hence the height is always less than `SMT_DEPTH`, the leaf
                // and root are not included.
                if let Some(hash) = overlay.node_mutations.get(&sibling) {
                    path_nodes[height] = *hash;
                }
            }

            // Update leaf if it was modified in this overlay
            if let Some(&(key, value)) = overlay.account_updates.get(&leaf.index()) {
                leaf = if value == EMPTY_WORD {
                    SmtLeaf::new_empty(leaf.index())
                } else {
                    SmtLeaf::new_single(key, value)
                };
            }
        }

        // Build the Merkle path directly from the reconstructed nodes
        // No need for build_dense_path since all nodes have actual values (not sentinels)
        let dense: Vec<Word> = path_nodes.iter().rev().copied().collect();
        let path = MerklePath::new(dense);
        let path = SparseMerklePath::try_from(path).ok()?;
        Some((path, leaf))
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Computes and applies mutations in one operation.
    ///
    /// This is a convenience method primarily for testing.
    pub fn compute_and_apply_mutations(
        &mut self,
        account_commitments: impl IntoIterator<Item = (AccountId, Word)>,
    ) -> Result<(), HistoricalError> {
        let mutations = self.compute_mutations(account_commitments)?;
        self.apply_mutations(mutations)
    }

    /// Computes mutations relative to the latest state.
    pub fn compute_mutations(
        &self,
        account_commitments: impl IntoIterator<Item = (AccountId, Word)>,
    ) -> Result<AccountMutationSet, HistoricalError> {
        Ok(self.latest.compute_mutations(account_commitments)?)
    }

    /// Applies mutations and advances to the next block.
    ///
    /// This method:
    /// 1. Applies the mutations to the latest tree, getting back reversion data
    /// 2. Stores the reversion data as a historical overlay
    /// 3. Advances the block number
    /// 4. Prunes old overlays if exceeding `MAX_HISTORY`
    pub fn apply_mutations(
        &mut self,
        mutations: AccountMutationSet,
    ) -> Result<(), HistoricalError> {
        // Apply mutations and get reversion data
        let rev = self.latest.apply_mutations_with_reversion(mutations)?;

        // Store reversion data for current block before advancing
        let block_num = self.block_number;
        let overlay = HistoricalOverlay::new(block_num, rev);
        self.overlays.insert(block_num, overlay);

        // Advance to next block
        self.block_number = block_num.child();

        // Prune old history if needed
        Self::drain_excess(&mut self.overlays);

        Ok(())
    }
}
