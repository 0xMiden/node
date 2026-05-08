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
/// Preserves the existing `store_sync_checkpoint` if a row already exists, so the mempool-driven
/// chain tip update doesn't clobber the sync watermark.
///
/// # Raw SQL
///
/// ```sql
/// INSERT INTO chain_state (id, block_num, block_header)
/// VALUES (0, ?1, ?2)
/// ON CONFLICT(id) DO UPDATE SET
///     block_num = excluded.block_num,
///     block_header = excluded.block_header
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
             block_num = excluded.block_num, \
             block_header = excluded.block_header",
    )
    .bind::<BigInt, _>(block_num_val)
    .bind::<Binary, _>(&header_bytes)
    .execute(conn)?;
    Ok(())
}

/// Returns the persisted store-sync checkpoint, or `None` if either:
/// - the row hasn't been initialized (first-ever startup), or
/// - the row exists but has never run a successful catch-up.
///
/// # Raw SQL
///
/// ```sql
/// SELECT store_sync_checkpoint FROM chain_state WHERE id = 0
/// ```
pub fn read_store_sync_checkpoint(
    conn: &mut SqliteConnection,
) -> Result<Option<BlockNumber>, DatabaseError> {
    let row: Option<Option<i64>> = schema::chain_state::table
        .filter(schema::chain_state::id.eq(0))
        .select(schema::chain_state::store_sync_checkpoint)
        .first(conn)
        .optional()?;
    Ok(row.flatten().map(conversions::block_num_from_i64))
}

/// Monotonically advances `store_sync_checkpoint` to the given block number.
///
/// Returns `Ok(())` regardless of whether the row was updated.
///
/// # Raw SQL
///
/// ```sql
/// UPDATE chain_state
/// SET store_sync_checkpoint = ?1
/// WHERE id = 0
///   AND (store_sync_checkpoint IS NULL OR store_sync_checkpoint < ?1)
/// ```
pub fn set_store_sync_checkpoint(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = conversions::block_num_to_i64(block_num);
    diesel::update(
        schema::chain_state::table.filter(schema::chain_state::id.eq(0)).filter(
            schema::chain_state::store_sync_checkpoint
                .is_null()
                .or(schema::chain_state::store_sync_checkpoint.lt(block_num_val)),
        ),
    )
    .set(schema::chain_state::store_sync_checkpoint.eq(Some(block_num_val)))
    .execute(conn)?;
    Ok(())
}
