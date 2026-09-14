use std::ops::RangeInclusive;

use miden_protocol::block::BlockNumber;
use thiserror::Error;

use crate::generated as proto;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidBlockRange {
    #[error("start ({start}) greater than end ({end})")]
    StartGreaterThanEnd { start: BlockNumber, end: BlockNumber },
}

impl proto::rpc::BlockRange {
    /// Converts the block range into an inclusive range.
    ///
    /// A `RangeInclusive` is empty exactly when `start > end`, so that case is
    /// reported as [`InvalidBlockRange::StartGreaterThanEnd`]. Equal endpoints
    /// are a valid single-block range.
    pub fn into_inclusive_range<T: From<InvalidBlockRange>>(
        self,
    ) -> Result<RangeInclusive<BlockNumber>, T> {
        let block_range = RangeInclusive::new(self.block_from.into(), self.block_to.into());

        if block_range.start() > block_range.end() {
            return Err(InvalidBlockRange::StartGreaterThanEnd {
                start: *block_range.start(),
                end: *block_range.end(),
            }
            .into());
        }

        Ok(block_range)
    }
}

impl From<RangeInclusive<BlockNumber>> for proto::rpc::BlockRange {
    fn from(range: RangeInclusive<BlockNumber>) -> Self {
        Self {
            block_from: range.start().as_u32(),
            block_to: range.end().as_u32(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn range(from: u32, to: u32) -> proto::rpc::BlockRange {
        proto::rpc::BlockRange { block_from: from, block_to: to }
    }

    #[test]
    fn into_inclusive_range_rejects_start_greater_than_end() {
        let err = range(5, 4)
            .into_inclusive_range::<InvalidBlockRange>()
            .expect_err("inverted range must be rejected");
        assert_eq!(
            err,
            InvalidBlockRange::StartGreaterThanEnd {
                start: BlockNumber::from(5u32),
                end: BlockNumber::from(4u32),
            }
        );
    }

    #[test]
    fn into_inclusive_range_accepts_single_block() {
        let got = range(7, 7)
            .into_inclusive_range::<InvalidBlockRange>()
            .expect("start == end is a valid inclusive range");
        assert_eq!(*got.start(), BlockNumber::from(7u32));
        assert_eq!(*got.end(), BlockNumber::from(7u32));
    }

    #[test]
    fn into_inclusive_range_accepts_ascending_span() {
        let got = range(1, 3)
            .into_inclusive_range::<InvalidBlockRange>()
            .expect("ascending range must be accepted");
        assert_eq!(*got.start(), BlockNumber::from(1u32));
        assert_eq!(*got.end(), BlockNumber::from(3u32));
    }
}
