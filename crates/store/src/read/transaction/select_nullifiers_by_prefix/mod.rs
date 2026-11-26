use std::ops::RangeInclusive;

use miden_node_db::sqlite::InList;
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamLimiter,
    QueryParamNullifierPrefixLimit,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use super::ReadTransaction;
use crate::db::NullifierInfo;
use crate::db::pagination::{Page, complete_blocks_page};
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the page of nullifiers created within `block_range` whose 16-bit prefix is one of
    /// `nullifier_prefixes`, ordered by block number.
    ///
    /// Clients send only prefixes so that the node does not learn which nullifiers they track. At
    /// most 1000 prefixes are accepted. The page starts at the beginning of `block_range` and never
    /// splits a block.
    pub fn select_nullifiers_by_prefix(
        &self,
        nullifier_prefixes: &[u16],
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<Page<NullifierInfo, BlockNumber>, DatabaseError> {
        // Size calculation: max 2^16 nullifiers per block × 36 bytes per nullifier = ~2.25MB
        pub const NULLIFIER_BYTES: usize = 32; // digest size (nullifier)
        pub const BLOCK_NUM_BYTES: usize = 4; // 32 bits per block number
        pub const ROW_OVERHEAD_BYTES: usize = NULLIFIER_BYTES + BLOCK_NUM_BYTES; // 36 bytes
        pub const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;
        // Pagination reports the last fully-included block, so it only makes progress if every
        // block fits within a single page. A block that exceeded `MAX_ROWS` nullifiers would fail
        // every page that starts at that block.
        const _: () = assert!(
            miden_protocol::MAX_INPUT_NOTES_PER_BLOCK <= MAX_ROWS,
            "a block's nullifiers must fit in one response page or pagination cannot make progress",
        );

        let (block_from, block_to) = block_range.into_inner();
        if block_from > block_to {
            return Err(DatabaseError::InvalidBlockRange { from: block_from, to: block_to });
        }

        QueryParamNullifierPrefixLimit::check(nullifier_prefixes.len())?;

        let prefixes = InList::from_values(nullifier_prefixes);
        // Request an additional row so we can determine whether this is the last page.
        let limit = i64::try_from(MAX_ROWS + 1).expect("limit fits within i64");

        let nullifiers =
            self.inner.query(SQL, &[&prefixes, &block_from, &block_to, &limit], |row| {
                Ok(NullifierInfo {
                    nullifier: row.get::<Nullifier>(0)?,
                    block_num: row.get::<BlockNumber>(1)?,
                })
            })?;

        complete_blocks_page(nullifiers, MAX_ROWS, |info| info.block_num)
    }
}
