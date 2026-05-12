//! Chain state queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_protocol::block::{BlockHeader, BlockNumber};

use crate::db::models::conv as conversions;
use crate::db::schema;

// QUERIES
// ================================================================================================

/// Inserts or replaces the singleton chain state row.
///
/// Preserves the existing `next_block_to_sync` if a row already exists, so the mempool-driven
/// chain tip update doesn't clobber it.
///
/// # Raw SQL
///
/// ```sql
/// INSERT INTO chain_state (id, block_num, block_header)
/// VALUES (0, ?1, ?2)
/// ON CONFLICT(id) DO UPDATE SET
///     block_num = ?1,
///     block_header = ?2
/// ```
pub fn upsert_chain_state(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    block_header: &BlockHeader,
) -> Result<(), DatabaseError> {
    use diesel::sql_types::{BigInt, Binary};

    let block_num_val = conversions::block_num_to_i64(block_num);
    let header_bytes = conversions::block_header_to_bytes(block_header);

    diesel::sql_query(
        "INSERT INTO chain_state (id, block_num, block_header) \
         VALUES (0, ?1, ?2) \
         ON CONFLICT(id) DO UPDATE SET \
             block_num = ?1, \
             block_header = ?2",
    )
    .bind::<BigInt, _>(block_num_val)
    .bind::<Binary, _>(&header_bytes)
    .execute(conn)?;
    Ok(())
}

/// Returns the next chain block the ntx-builder should ingest from the store on its next
/// startup catch-up. Defaults to [`BlockNumber::GENESIS`] for a freshly migrated DB.
///
/// # Raw SQL
///
/// ```sql
/// SELECT next_block_to_sync FROM chain_state WHERE id = 0
/// ```
pub fn read_next_block_to_sync(conn: &mut SqliteConnection) -> Result<BlockNumber, DatabaseError> {
    let row: Option<i64> = schema::chain_state::table
        .filter(schema::chain_state::id.eq(0))
        .select(schema::chain_state::next_block_to_sync)
        .first(conn)
        .optional()?;
    Ok(row.map_or(BlockNumber::GENESIS, conversions::block_num_from_i64))
}

/// Monotonically advances `next_block_to_sync` to the given block number.
///
/// Returns `Ok(())` regardless of whether the row was updated.
///
/// # Raw SQL
///
/// ```sql
/// UPDATE chain_state
/// SET next_block_to_sync = ?1
/// WHERE id = 0
///   AND next_block_to_sync < ?1
/// ```
pub fn set_next_block_to_sync(
    conn: &mut SqliteConnection,
    next_block_to_sync: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = conversions::block_num_to_i64(next_block_to_sync);
    diesel::update(
        schema::chain_state::table
            .filter(schema::chain_state::id.eq(0))
            .filter(schema::chain_state::next_block_to_sync.lt(block_num_val)),
    )
    .set(schema::chain_state::next_block_to_sync.eq(block_num_val))
    .execute(conn)?;
    Ok(())
}
