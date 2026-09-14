use std::ops::RangeInclusive;

use miden_protobuf::{BuildUnchecked, ConversionResultExt, Verify, VerifyWith};
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use thiserror::Error;

use crate::errors::ConversionError;
use crate::generated as proto;

impl BuildUnchecked for proto::rpc::DecodedBlockSubscriptionResponse {
    type Output = (SignedBlock, BlockNumber);
    type Error = ConversionError;

    /// Check block consistency without verifying signatures or linkage against a trusted parent.
    /// The caller must verify the block against trusted chain state before applying it. The
    /// committed chain tip remains an upstream claim.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        // SAFETY: The caller must authenticate the block before applying it. This conversion checks
        // consistency only.
        let block = self.block.build_unchecked().context("block")?;
        Ok((block, self.committed_chain_tip.into()))
    }
}

impl VerifyWith<&BlockHeader> for proto::rpc::DecodedBlockSubscriptionResponse {
    type Verified = (SignedBlock, BlockNumber);
    type Error = ConversionError;

    /// Verify the block against a trusted parent header. This does not re-execute transactions or
    /// validate account and nullifier state transitions. The committed chain tip remains an
    /// upstream claim.
    fn verify_with(self, parent: &BlockHeader) -> Result<Self::Verified, Self::Error> {
        let block = self.block.verify_with(parent).context("block")?;
        Ok((block, self.committed_chain_tip.into()))
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidBlockRange {
    #[error("start ({start}) greater than end ({end})")]
    StartGreaterThanEnd { start: BlockNumber, end: BlockNumber },
}

impl Verify for proto::rpc::DecodedBlockRange {
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

    fn range(from: u32, to: u32) -> proto::rpc::DecodedBlockRange {
        use crate::DecodeMessage;
        proto::rpc::BlockRange { block_from: from, block_to: to }
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
}
