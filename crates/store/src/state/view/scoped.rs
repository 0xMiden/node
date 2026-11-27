//! Proof-of-validation block-number types issued by [`StateView`](super::StateView).
//!
//! Tip-scoped database queries take these types instead of raw block numbers, so callers validate the requested height against
//! the pinned snapshot or, during startup, the committed SQLite tip.
//!
//! Chain tips are monotonic, so a value issued by an older view remains valid for any later
//! state — holding one across view lifetimes is sound, if pointless.

use std::ops::Deref;

use miden_protocol::block::BlockNumber;

/// A block number proven to be at or below the issuing view's chain tip.
#[derive(Debug, Clone, Copy)]
pub struct ScopedBlockNum(BlockNumber);

impl ScopedBlockNum {
    /// Constructs a bound validated against the snapshot or startup tip.
    pub(in crate::state) fn new(block_num: BlockNumber) -> Self {
        Self(block_num)
    }

    /// Constructs a scoped block number without validation.
    ///
    /// Test-only: lets database tests exercise scoped queries without a running state.
    #[cfg(test)]
    pub(crate) fn new_unchecked(block_num: BlockNumber) -> Self {
        Self(block_num)
    }
}

/// The validated block number is read by dereferencing (`*scoped`); [`DerefMut`] is deliberately
/// not implemented, as mutating the inner value would invalidate the proof.
///
/// [`DerefMut`]: std::ops::DerefMut
impl Deref for ScopedBlockNum {
    type Target = BlockNumber;

    fn deref(&self) -> &BlockNumber {
        &self.0
    }
}
