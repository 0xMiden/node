//! Proof-of-validation block-number types issued by [`StateView`](super::StateView).
//!
//! Tip-scoped database queries take these types instead of raw block numbers, so a query whose
//! bound was not validated against a state view's tip is not expressible: the only constructors
//! live on [`StateView`](super::StateView), which checks the bound against its pinned snapshot.
//!
//! Chain tips are monotonic, so a value issued by an older view remains valid for any later
//! state — holding one across view lifetimes is sound, if pointless.

use std::ops::{Deref, RangeInclusive};

use miden_protocol::block::BlockNumber;

/// A block number proven to be at or below the issuing view's chain tip.
#[derive(Debug, Clone, Copy)]
pub struct ScopedBlockNum(BlockNumber);

impl ScopedBlockNum {
    /// Issued by [`StateView`](super::StateView) after validating the bound against its tip.
    pub(super) fn new(block_num: BlockNumber) -> Self {
        Self(block_num)
    }

    /// Constructs a scoped block number without validation.
    ///
    /// Test-only: lets database tests exercise scoped queries without a running state.
    #[cfg(test)]
    pub(crate) fn new_unchecked(block_num: BlockNumber) -> Self {
        Self(block_num)
    }

    /// Derives a scoped range ending at this validated block number.
    ///
    /// Sound for any `start` because only a range's upper bound carries the proof obligation.
    /// A `start` beyond this block number would however produce an empty range, which the range
    /// queries reject as an invalid block range. Used for paginating over a validated bound in
    /// sub-ranges.
    pub(crate) fn range_from(self, start: BlockNumber) -> ScopedBlockRange {
        debug_assert!(start <= self.0, "derived range start {start} exceeds its end {}", self.0);
        ScopedBlockRange(start..=self.0)
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

/// A block range whose upper bound is proven to be at or below the issuing view's chain tip.
#[derive(Debug, Clone)]
pub struct ScopedBlockRange(RangeInclusive<BlockNumber>);

impl ScopedBlockRange {
    /// Issued by [`StateView`](super::StateView) after validating the range against its tip.
    pub(super) fn new(range: RangeInclusive<BlockNumber>) -> Self {
        Self(range)
    }

    /// Constructs a scoped block range without validation.
    ///
    /// Test-only: lets database tests exercise scoped queries without a running state.
    #[cfg(test)]
    pub(crate) fn new_unchecked(range: RangeInclusive<BlockNumber>) -> Self {
        Self(range)
    }

    /// Returns the start of the validated range.
    pub(crate) fn start(&self) -> BlockNumber {
        *self.0.start()
    }

    /// Returns the end of the validated range.
    pub(crate) fn end(&self) -> BlockNumber {
        *self.0.end()
    }

    /// Returns the end of the validated range as a scoped block number.
    ///
    /// Sound because the range's upper bound is exactly what its proof covers.
    pub(crate) fn scoped_end(&self) -> ScopedBlockNum {
        ScopedBlockNum(*self.0.end())
    }

    /// Returns the validated range.
    pub(crate) fn into_inner(self) -> RangeInclusive<BlockNumber> {
        self.0
    }
}
