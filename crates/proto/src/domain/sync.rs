use std::collections::HashMap;

use miden_protobuf::{ConversionError, ConversionResultExt, Verify};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::generated as proto;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq)]
pub struct PaginationInfo {
    pub chain_tip: BlockNumber,
    pub block_num: BlockNumber,
}

impl Verify for proto::rpc::DecodedPaginationInfo {
    type Verified = PaginationInfo;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        if self.block_num > self.chain_tip {
            return Err(ConversionError::message("last checked block exceeds chain tip")
                .context("block_num"));
        }

        Ok(PaginationInfo {
            chain_tip: self.chain_tip.into(),
            block_num: self.block_num.into(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SyncNullifiersResponse {
    pub pagination_info: PaginationInfo,
    /// Maps each nullifier to the block that consumed the note.
    pub nullifiers: HashMap<Nullifier, BlockNumber>,
}

impl Verify for proto::rpc::DecodedSyncNullifiersResponse {
    type Verified = SyncNullifiersResponse;
    type Error = ConversionError;

    /// Check response consistency. The caller must check the requested block range and prefixes.
    /// The response does not contain proofs of nullifier inclusion or completeness.
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let pagination_info = self.pagination_info.verify().context("pagination_info")?;
        let mut nullifiers = HashMap::with_capacity(self.nullifiers.as_slice().len());
        for (index, update) in self.nullifiers.into_inner().into_iter().enumerate() {
            let block_num = BlockNumber::from(update.block_num);
            if block_num > pagination_info.block_num {
                return Err(ConversionError::message("nullifier block exceeds last checked block")
                    .context(format!("nullifiers[{index}].block_num")));
            }
            let nullifier = Nullifier::from_raw(update.nullifier);
            if nullifiers.insert(nullifier, block_num).is_some() {
                return Err(ConversionError::message(format!("duplicate nullifier {nullifier}"))
                    .context(format!("nullifiers[{index}].nullifier")));
            }
        }

        Ok(SyncNullifiersResponse { pagination_info, nullifiers })
    }
}
