//! Chain state queries and models.

use diesel::prelude::*;
use diesel::upsert::excluded;
use miden_node_db::DatabaseError;
use miden_protocol::Word;
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

/// Upserts the singleton chain state row, persisting the chain tip header and the associated
/// partial chain MMR. On conflict only the tip columns are updated, so the `genesis_commitment`
/// set at bootstrap is retained.
///
/// # Raw SQL
///
/// ```sql
/// INSERT INTO chain_state (id, block_num, block_header, chain_mmr)
/// VALUES (0, ?1, ?2, ?3)
/// ON CONFLICT(id) DO UPDATE SET
///     block_num = excluded.block_num,
///     block_header = excluded.block_header,
///     chain_mmr = excluded.chain_mmr
/// ```
pub fn upsert_chain_state(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    block_header: &BlockHeader,
    chain_mmr: &PartialMmr,
) -> Result<(), DatabaseError> {
    use schema::chain_state::columns;

    let row = ChainStateInsert {
        id: 0,
        block_num: conversions::block_num_to_i64(block_num),
        block_header: conversions::block_header_to_bytes(block_header),
        chain_mmr: chain_mmr.to_bytes(),
    };
    diesel::insert_into(schema::chain_state::table)
        .values(&row)
        .on_conflict(columns::id)
        .do_update()
        .set((
            columns::block_num.eq(excluded(columns::block_num)),
            columns::block_header.eq(excluded(columns::block_header)),
            columns::chain_mmr.eq(excluded(columns::chain_mmr)),
        ))
        .execute(conn)?;
    Ok(())
}

/// Persists the genesis block commitment into the singleton chain state row. Called once at
/// bootstrap, after the genesis chain state has been inserted.
///
/// # Raw SQL
///
/// ```sql
/// UPDATE chain_state SET genesis_commitment = ?1 WHERE id = 0
/// ```
pub fn set_genesis_commitment(
    conn: &mut SqliteConnection,
    genesis_commitment: &Word,
) -> Result<(), DatabaseError> {
    diesel::update(schema::chain_state::table.find(0i32))
        .set(
            schema::chain_state::genesis_commitment
                .eq(conversions::word_to_bytes(genesis_commitment)),
        )
        .execute(conn)?;
    Ok(())
}

/// Reads the genesis block commitment from the singleton chain state row.
///
/// # Raw SQL
///
/// ```sql
/// SELECT genesis_commitment FROM chain_state WHERE id = 0
/// ```
///
/// # Errors
///
/// - If the genesis commitment had not been set
pub fn select_genesis_commitment(conn: &mut SqliteConnection) -> Result<Word, DatabaseError> {
    let commitment: Option<Vec<u8>> = schema::chain_state::table
        .find(0i32)
        .select(schema::chain_state::genesis_commitment)
        .first(conn)?;

    let commitment = commitment.ok_or(diesel::result::Error::NotFound)?;

    Word::read_from_bytes(&commitment)
        .map_err(|e| DatabaseError::deserialization("genesis commitment", e))
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
