use std::ops::RangeInclusive;

use miden_protobuf::{BuildUnchecked, ConversionResultExt, Verify, VerifyWith};
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::protocol_config::ProtocolConfig;
use thiserror::Error;

use super::protocol_config::verify_protocol_config_commitment;
use crate::errors::ConversionError;
use crate::generated as proto;

impl BuildUnchecked for proto::miden::node::v1::DecodedBlockSubscriptionResponse {
    type Output = (SignedBlock, BlockNumber, Option<ProtocolConfig>);
    type Error = ConversionError;

    /// Check block consistency without verifying signatures or linkage against a trusted parent.
    /// The caller must verify the block against trusted chain state before applying it. The
    /// committed chain tip remains an upstream claim.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        // SAFETY: The caller must authenticate the block before applying it. This conversion checks
        // consistency only.
        let block = self.block.build_unchecked().context("block")?;
        let protocol_config = self.protocol_config.try_map(|config| {
            verify_protocol_config_commitment(
                config.verify().map_err(ConversionError::new)?,
                block.header(),
            )
        })?;
        Ok((block, self.committed_chain_tip.into(), protocol_config))
    }
}

impl VerifyWith<&BlockHeader> for proto::miden::node::v1::DecodedBlockSubscriptionResponse {
    type Verified = (SignedBlock, BlockNumber, Option<ProtocolConfig>);
    type Error = ConversionError;

    /// Verify the block against a trusted parent header. This does not re-execute transactions or
    /// validate account and nullifier state transitions. The committed chain tip remains an
    /// upstream claim.
    fn verify_with(self, parent: &BlockHeader) -> Result<Self::Verified, Self::Error> {
        let block = self.block.verify_with(parent).context("block")?;
        let protocol_config = self.protocol_config.try_map(|config| {
            verify_protocol_config_commitment(
                config.verify().map_err(ConversionError::new)?,
                block.header(),
            )
        })?;
        Ok((block, self.committed_chain_tip.into(), protocol_config))
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidBlockRange {
    #[error("start ({start}) greater than end ({end})")]
    StartGreaterThanEnd { start: BlockNumber, end: BlockNumber },
}

impl Verify for proto::miden::node::v1::DecodedBlockRange {
    type Verified = RangeInclusive<BlockNumber>;
    type Error = InvalidBlockRange;

    /// Converts the block range into an inclusive range.
    ///
    /// A `RangeInclusive` is empty exactly when `start > end`, so that case is
    /// reported as [`InvalidBlockRange::StartGreaterThanEnd`]. Equal endpoints
    /// are a valid single-block range.
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let block_range = RangeInclusive::new(self.block_from.into(), self.block_to.into());

        if block_range.start() > block_range.end() {
            return Err(InvalidBlockRange::StartGreaterThanEnd {
                start: *block_range.start(),
                end: *block_range.end(),
            });
        }

        Ok(block_range)
    }
}

impl From<RangeInclusive<BlockNumber>> for proto::miden::node::v1::BlockRange {
    fn from(range: RangeInclusive<BlockNumber>) -> Self {
        Self {
            block_from: range.start().as_u32(),
            block_to: range.end().as_u32(),
        }
    }
}

/// A synchronization delta with an explicit target and an optional bootstrap lower bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRange {
    pub from_exclusive: Option<BlockNumber>,
    pub target: BlockNumber,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidSyncRange {
    #[error("synchronization target is required")]
    MissingTarget,
    #[error("start ({start}) greater than target ({target})")]
    StartGreaterThanTarget { start: BlockNumber, target: BlockNumber },
}

impl SyncRange {
    /// Returns the inclusive store range, or no rows when the client already has the target.
    pub fn database_range(self) -> Option<RangeInclusive<BlockNumber>> {
        let start = match self.from_exclusive {
            None => BlockNumber::GENESIS,
            Some(from) if from >= self.target => return None,
            Some(from) => BlockNumber::from(from.as_u32().checked_add(1)?),
        };
        Some(start..=self.target)
    }
}

impl From<RangeInclusive<BlockNumber>> for SyncRange {
    fn from(range: RangeInclusive<BlockNumber>) -> Self {
        Self {
            from_exclusive: range.start().checked_sub(1),
            target: *range.end(),
        }
    }
}

impl Verify for proto::miden::node::v1::DecodedStateDeltaRange {
    type Verified = SyncRange;
    type Error = InvalidSyncRange;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let target = self
            .to_block_inclusive
            .map(BlockNumber::from)
            .ok_or(InvalidSyncRange::MissingTarget)?;
        let from_exclusive = self.from_block_exclusive.map(BlockNumber::from);
        if let Some(start) = from_exclusive {
            if start > target {
                return Err(InvalidSyncRange::StartGreaterThanTarget { start, target });
            }
        }
        Ok(SyncRange { from_exclusive, target })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn range(from: u32, to: u32) -> proto::miden::node::v1::DecodedBlockRange {
        use crate::DecodeMessage;
        proto::miden::node::v1::BlockRange { block_from: from, block_to: to }
            .decode_fields()
            .unwrap()
    }

    #[test]
    fn verify_rejects_start_greater_than_end() {
        let err = range(5, 4).verify().expect_err("inverted range must be rejected");
        assert_eq!(
            err,
            InvalidBlockRange::StartGreaterThanEnd {
                start: BlockNumber::from(5u32),
                end: BlockNumber::from(4u32),
            }
        );
    }

    #[test]
    fn verify_accepts_single_block() {
        let got = range(7, 7).verify().expect("start == end is a valid inclusive range");
        assert_eq!(*got.start(), BlockNumber::from(7u32));
        assert_eq!(*got.end(), BlockNumber::from(7u32));
    }

    #[test]
    fn verify_accepts_ascending_span() {
        let got = range(1, 3).verify().expect("ascending range must be accepted");
        assert_eq!(*got.start(), BlockNumber::from(1u32));
        assert_eq!(*got.end(), BlockNumber::from(3u32));
    }

    fn delta_range(from: Option<u32>, target: Option<u32>) -> Result<SyncRange, InvalidSyncRange> {
        use crate::DecodeMessage;
        proto::miden::node::v1::StateDeltaRange {
            from_block_exclusive: from,
            to_block_inclusive: target,
        }
        .decode_fields()
        .unwrap()
        .verify()
    }

    #[test]
    fn delta_range_bootstrap_includes_genesis() {
        assert_eq!(delta_range(None, Some(0)).unwrap().database_range(), Some(0.into()..=0.into()));
        assert_eq!(delta_range(None, Some(5)).unwrap().database_range(), Some(0.into()..=5.into()));
    }

    #[test]
    fn delta_range_excludes_the_client_block() {
        assert_eq!(
            delta_range(Some(0), Some(1)).unwrap().database_range(),
            Some(1.into()..=1.into())
        );
        assert_eq!(
            delta_range(Some(4), Some(9)).unwrap().database_range(),
            Some(5.into()..=9.into())
        );
    }

    #[test]
    fn delta_range_equal_bounds_are_empty_even_at_maximum() {
        for block in [0, 7, u32::MAX] {
            let range = delta_range(Some(block), Some(block)).unwrap();
            assert_eq!(range.target, BlockNumber::from(block));
            assert!(range.database_range().is_none());
        }
    }

    #[test]
    fn delta_range_requires_target_presence() {
        assert_eq!(delta_range(None, None), Err(InvalidSyncRange::MissingTarget));
        assert_eq!(delta_range(Some(0), None), Err(InvalidSyncRange::MissingTarget));
    }

    #[test]
    fn delta_range_rejects_reversed_bounds() {
        assert_eq!(
            delta_range(Some(5), Some(4)),
            Err(InvalidSyncRange::StartGreaterThanTarget { start: 5.into(), target: 4.into() }),
        );
    }
}
