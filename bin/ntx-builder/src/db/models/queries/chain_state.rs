//! Chain state queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::utils::serde::{Deserializable, Serializable};

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
    pub chain_mmr: Vec<u8>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::chain_state)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct ChainStateRow {
    block_num: i64,
    block_header: Vec<u8>,
    chain_mmr: Vec<u8>,
}

// QUERIES
// ================================================================================================

/// Inserts or replaces the singleton chain state row, persisting the chain tip header and the
/// associated partial chain MMR.
///
/// # Raw SQL
///
/// ```sql
/// INSERT OR REPLACE INTO chain_state (id, block_num, block_header, chain_mmr)
/// VALUES (0, ?1, ?2, ?3)
/// ```
pub fn upsert_chain_state(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    block_header: &BlockHeader,
    chain_mmr: &PartialMmr,
) -> Result<(), DatabaseError> {
    let row = ChainStateInsert {
        id: 0,
        block_num: conversions::block_num_to_i64(block_num),
        block_header: conversions::block_header_to_bytes(block_header),
        chain_mmr: chain_mmr.to_bytes(),
    };
    diesel::replace_into(schema::chain_state::table).values(&row).execute(conn)?;
    Ok(())
}

/// Reads the singleton chain state row, returning the persisted block number, header, and chain
/// MMR if any block has been applied locally.
///
/// # Raw SQL
///
/// ```sql
/// SELECT block_num, block_header, chain_mmr FROM chain_state WHERE id = 0
/// ```
pub fn select_chain_state(
    conn: &mut SqliteConnection,
) -> Result<Option<(BlockNumber, BlockHeader, PartialMmr)>, DatabaseError> {
    let row: Option<ChainStateRow> = schema::chain_state::table
        .find(0i32)
        .select(ChainStateRow::as_select())
        .first(conn)
        .optional()?;

    row.map(|ChainStateRow { block_num, block_header, chain_mmr }| {
        let block_num = conversions::block_num_from_i64(block_num);
        let header = BlockHeader::read_from_bytes(&block_header)
            .map_err(|e| DatabaseError::deserialization("block header", e))?;
        let mmr = PartialMmr::read_from_bytes(&chain_mmr)
            .map_err(|e| DatabaseError::deserialization("chain mmr", e))?;
        Ok((block_num, header, mmr))
    })
    .transpose()
}
