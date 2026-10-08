//! Returns the nullifiers that match a set of prefixes within a block range.

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamLimiter,
    QueryParamNullifierPrefixLimit,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::db::NullifierInfo;
use crate::db::pagination::{Page, Paginated, complete_blocks_page};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockNum;

const SQL: &str = include_str!("select_nullifiers_by_prefix.sql");

/// Paginated query over the nullifiers created up to `block_to` whose most significant
/// `prefix_len` bits match one of `nullifier_prefixes`, ordered by block number.
///
/// Clients send only prefixes so that the node does not learn which nullifiers they track. Only
/// 16-bit prefixes are supported, with at most 1000 prefixes per query. The cursor is the block
/// where a page starts, and a page never splits a block.
#[derive(Debug, Clone)]
pub(crate) struct NullifiersByPrefix {
    prefix_len: u8,
    nullifier_prefixes: Vec<u16>,
    block_to: BlockNumber,
}

impl NullifiersByPrefix {
    /// Creates the query for `nullifier_prefixes` of `prefix_len` bits up to and including
    /// `block_to`.
    pub(crate) fn new(
        prefix_len: u8,
        nullifier_prefixes: Vec<u16>,
        block_to: ScopedBlockNum,
    ) -> Self {
        Self {
            prefix_len,
            nullifier_prefixes,
            block_to: *block_to,
        }
    }
}

impl Paginated for NullifiersByPrefix {
    type Item = NullifierInfo;
    type Cursor = BlockNumber;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &BlockNumber,
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

        assert_eq!(self.prefix_len, 16, "Only 16-bit prefixes are supported");

        let (block_from, block_to) = (*next, self.block_to);
        if block_from > block_to {
            return Err(DatabaseError::InvalidBlockRange { from: block_from, to: block_to });
        }

        QueryParamNullifierPrefixLimit::check(self.nullifier_prefixes.len())?;

        let prefixes = InList::from_values(&self.nullifier_prefixes);
        // Request an additional row so we can determine whether this is the last page.
        let limit = i64::try_from(MAX_ROWS + 1).expect("limit fits within i64");

        let nullifiers = tx.query(SQL, &[&prefixes, &block_from, &block_to, &limit], |row| {
            Ok(NullifierInfo {
                nullifier: row.get::<Nullifier>(0)?,
                block_num: row.get::<BlockNumber>(1)?,
            })
        })?;

        complete_blocks_page(nullifiers, MAX_ROWS, |info| info.block_num)
    }
}
