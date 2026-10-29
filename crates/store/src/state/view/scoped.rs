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

use crate::errors::DatabaseError;

/// A block number proven to be at or below the issuing view's chain tip.
#[derive(Debug, Clone, Copy)]
pub struct ScopedBlockNum(BlockNumber);

impl ScopedBlockNum {
    /// Issued by [`StateView`](super::StateView) after validating the bound against its tip.
    pub(super) fn new(block_num: BlockNumber) -> Self {
        Self(block_num)
    }

    /// Returns a range ending at this validated block, rejecting starts beyond it.
    ///
    /// Both endpoints must be within the validated bound because either can be used as a scoped
    /// block number.
    pub fn range_from(self, start: BlockNumber) -> Result<ScopedBlockRange, DatabaseError> {
        if start > self.0 {
            return Err(DatabaseError::InvalidBlockRange { from: start, to: self.0 });
        }
        Ok(ScopedBlockRange(start..=self.0))
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

/// A block range whose upper bound is proven to be at or below the issuing view's chain tip.
#[derive(Debug, Clone)]
pub struct ScopedBlockRange(RangeInclusive<BlockNumber>);

impl ScopedBlockRange {
    /// Issued by [`StateView`](super::StateView) after validating the range against its tip.
    pub(super) fn new(range: RangeInclusive<BlockNumber>) -> Self {
        Self(range)
    }

    /// Constructs a scoped range without validation for database tests.
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

    /// Returns the start of a nonempty validated range as a scoped block number.
    ///
    /// Its lower bound cannot exceed the validated upper bound.
    pub fn scoped_start(&self) -> ScopedBlockNum {
        ScopedBlockNum(*self.0.start())
    }

    /// Returns the end of the validated range as a scoped block number.
    ///
    /// Sound because the range's upper bound is exactly what its proof covers.
    pub fn scoped_end(&self) -> ScopedBlockNum {
        ScopedBlockNum(*self.0.end())
    }

    /// Returns the validated range.
    pub(crate) fn into_inner(self) -> RangeInclusive<BlockNumber> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_from_accepts_starts_at_or_before_the_validated_block() {
        let target = ScopedBlockNum::new(10.into());
        for start in [BlockNumber::GENESIS, 9.into(), 10.into()] {
            let range = target.range_from(start).unwrap();
            assert_eq!(*range.scoped_start(), start);
            assert_eq!(*range.scoped_end(), *target);
        }
    }

    #[test]
    fn range_from_rejects_starts_beyond_the_validated_block() {
        let target = ScopedBlockNum::new(10.into());
        let start = BlockNumber::from(11);
        assert!(matches!(
            target.range_from(start),
            Err(DatabaseError::InvalidBlockRange { from, to }) if from == start && to == *target
        ));
    }
}
