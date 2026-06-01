//! Chain state queries and models.

use diesel::prelude::*;
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
    pub genesis_commitment: Vec<u8>,
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

/// Updates the tip columns (block number, header, and partial chain MMR) of the singleton chain
/// state row. The row is created once at bootstrap by [`insert_genesis_chain_state`], so this is a
/// plain update; the `genesis_commitment` column is set at bootstrap and never touched here.
///
/// # Raw SQL
///
/// ```sql
/// UPDATE chain_state
/// SET block_num = ?1, block_header = ?2, chain_mmr = ?3
/// WHERE id = 0
/// ```
pub fn update_chain_state_tip(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    block_header: &BlockHeader,
    chain_mmr: &PartialMmr,
) -> Result<(), DatabaseError> {
    diesel::update(schema::chain_state::table.find(0i32))
        .set((
            schema::chain_state::block_num.eq(conversions::block_num_to_i64(block_num)),
            schema::chain_state::block_header.eq(conversions::block_header_to_bytes(block_header)),
            schema::chain_state::chain_mmr.eq(chain_mmr.to_bytes()),
        ))
        .execute(conn)?;
    Ok(())
}

/// Inserts the singleton chain state row at bootstrap, seeding the tip columns from the genesis
/// block together with the genesis block commitment. The commitment satisfies the `NOT NULL`
/// constraint at insert time and is retained across all subsequent tip updates (see
/// [`update_chain_state_tip`]).
///
/// # Raw SQL
///
/// ```sql
/// INSERT INTO chain_state (id, block_num, block_header, chain_mmr, genesis_commitment)
/// VALUES (0, ?1, ?2, ?3, ?4)
/// ```
pub fn insert_genesis_chain_state(
    conn: &mut SqliteConnection,
    genesis_block_header: &BlockHeader,
    genesis_commitment: &Word,
) -> Result<(), DatabaseError> {
    assert_eq!(
        genesis_block_header.block_num(),
        BlockNumber::GENESIS,
        "bootstrap block number is not 0"
    );
    let row = ChainStateInsert {
        id: 0,
        block_num: conversions::block_num_to_i64(genesis_block_header.block_num()),
        block_header: conversions::block_header_to_bytes(genesis_block_header),
        chain_mmr: PartialMmr::default().to_bytes(),
        genesis_commitment: conversions::word_to_bytes(genesis_commitment),
    };
    diesel::insert_into(schema::chain_state::table).values(&row).execute(conn)?;
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
/// - If the singleton chain state row does not exist (database not bootstrapped)
pub fn select_genesis_commitment(conn: &mut SqliteConnection) -> Result<Word, DatabaseError> {
    let commitment: Vec<u8> = schema::chain_state::table
        .find(0i32)
        .select(schema::chain_state::genesis_commitment)
        .first(conn)?;

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
