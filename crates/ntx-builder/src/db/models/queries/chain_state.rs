//! Chain state queries and models.

use diesel::prelude::*;
use miden_protocol::block::{BlockHeader, BlockNumber};

use crate::db::errors::DatabaseError;
use crate::db::models::conv as conversions;
use crate::db::schema;

// MODELS
// ================================================================================================

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::chain_state)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ChainStateInsert {
    /// Singleton row ID. Always `0` to satisfy the `CHECK (id = 0)` constraint.
    pub id: i32,
    pub block_num: i64,
    pub block_header: Vec<u8>,
}

// QUERIES
// ================================================================================================

/// Inserts or replaces the singleton chain state row.
///
/// # Raw SQL
///
/// ```sql
/// INSERT OR REPLACE INTO chain_state (id, block_num, block_header)
/// VALUES (0, ?1, ?2)
/// ```
pub fn upsert_chain_state(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    block_header: &BlockHeader,
) -> Result<(), DatabaseError> {
    let row = ChainStateInsert {
        id: 0,
        block_num: conversions::block_num_to_i64(block_num),
        block_header: conversions::block_header_to_bytes(block_header),
    };
    diesel::replace_into(schema::chain_state::table).values(&row).execute(conn)?;
    Ok(())
}
