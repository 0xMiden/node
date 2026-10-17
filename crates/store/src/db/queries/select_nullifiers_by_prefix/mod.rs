//! Returns the nullifiers that match a set of prefixes within a block range.

use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamLimiter,
    QueryParamNullifierPrefixLimit,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::db::NullifierInfo;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_nullifiers_by_prefix.sql");

/// Returns nullifiers filtered by prefix within a block number range.
///
/// # Parameters
/// * `prefix_len`: Length of nullifier prefix in bits
///     - Must be exactly 16 bits
/// * `nullifier_prefixes`: List of nullifier prefixes to filter by
///     - Limit: 0 <= count <= 1000
///
/// Each value of the `nullifier_prefixes` is only the `prefix_len` most significant bits
/// of the nullifier of interest to the client. This hides the details of the specific
/// nullifier being requested. Currently the only supported prefix length is 16 bits.
///
/// # Returns
///
/// The matching nullifiers with the block at which they were created, and the last block that
/// the response covers. If the rows exceed the payload limit, the response does not include the
/// last block. The returned block number then shows how far the response goes.
pub(crate) fn select_nullifiers_by_prefix(
    tx: &ReadTx<'_>,
    prefix_len: u8,
    nullifier_prefixes: &[u16],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<(Vec<NullifierInfo>, BlockNumber), DatabaseError> {
    // Size calculation: max 2^16 nullifiers per block × 36 bytes per nullifier = ~2.25MB
    pub const NULLIFIER_BYTES: usize = 32; // digest size (nullifier)
    pub const BLOCK_NUM_BYTES: usize = 4; // 32 bits per block number
    pub const ROW_OVERHEAD_BYTES: usize = NULLIFIER_BYTES + BLOCK_NUM_BYTES; // 36 bytes
    pub const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;
    // Pagination reports the last fully-included block, so it only makes progress if every block
    // fits within a single page. A block that exceeded `MAX_ROWS` nullifiers would produce an empty
    // page and stall clients forever on that block.
    const _: () = assert!(
        miden_protocol::MAX_INPUT_NOTES_PER_BLOCK <= MAX_ROWS,
        "a block's nullifiers must fit in one response page or pagination cannot make progress",
    );

    assert_eq!(prefix_len, 16, "Only 16-bit prefixes are supported");

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    QueryParamNullifierPrefixLimit::check(nullifier_prefixes.len())?;

    let prefixes = InList::from_values(nullifier_prefixes);
    // Request an additional row so we can determine whether this is the last page.
    let limit = i64::try_from(MAX_ROWS + 1).expect("limit fits within i64");

    let mut nullifiers =
        tx.query(SQL, &[&prefixes, block_range.start(), block_range.end(), &limit], |row| {
            Ok(NullifierInfo {
                nullifier: row.get::<Nullifier>(0)?,
                block_num: row.get::<BlockNumber>(1)?,
            })
        })?;

    // Discard the last block in the response (assumes more than one block may be present)
    if let Some(last_block_num) = nullifiers.last().map(|info| info.block_num)
        && nullifiers.len() > MAX_ROWS
    {
        // All rows are in the genesis block only if that block holds more than `MAX_ROWS`
        // nullifiers, which the protocol limit prevents.
        let last_block_included = last_block_num.parent().ok_or_else(|| {
            DatabaseError::DataCorrupted(format!(
                "block {last_block_num} holds more than {MAX_ROWS} nullifiers"
            ))
        })?;
        nullifiers.retain(|info| info.block_num != last_block_num);

        Ok((nullifiers, last_block_included))
    } else {
        Ok((nullifiers, *block_range.end()))
    }
}
