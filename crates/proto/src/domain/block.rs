use std::ops::RangeInclusive;

use miden_protocol::block::BlockNumber;
use thiserror::Error;

use crate::generated as proto;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidBlockRange {
    #[error("start ({start}) greater than end ({end})")]
    StartGreaterThanEnd { start: BlockNumber, end: BlockNumber },
    #[error("empty range: start ({start})..end ({end})")]
    EmptyRange { start: BlockNumber, end: BlockNumber },
}

impl proto::rpc::BlockRange {
    /// Converts the block range into an inclusive range.
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

        if block_range.is_empty() {
            return Err(InvalidBlockRange::EmptyRange {
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
