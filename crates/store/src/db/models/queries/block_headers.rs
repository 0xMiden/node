use diesel::prelude::Insertable;
use diesel::query_dsl::methods::SelectDsl;
use diesel::{
    ExpressionMethods,
    OptionalExtension,
    QueryDsl,
    Queryable,
    QueryableByName,
    RunQueryDsl,
    Selectable,
    SelectableHelper,
    SqliteConnection,
};
use miden_crypto::Word;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_node_utils::limiter::{QueryParamBlockLimit, QueryParamLimiter};
use miden_protocol::block::{BlockHeader, BlockNumber, BlockProof};
use miden_protocol::utils::{Deserializable, Serializable};

use super::DatabaseError;
use crate::COMPONENT;
use crate::db::models::conv::SqlTypeConvert;
use crate::db::models::vec_raw_try_into;
use crate::db::schema;

/// Select a [`BlockHeader`] from the DB by its `block_num` using the given [`SqliteConnection`].
///
/// # Returns
///
/// When `block_num` is [None], the latest block header is returned. Otherwise, the block with
/// the given block height is returned.
///
/// ```sql
/// -- with argument
/// SELECT block_num, block_header
/// FROM block_headers
/// WHERE block_num = ?1
///
/// -- without argument
/// SELECT block_num, block_header
/// FROM block_headers
/// ORDER BY block_num DESC
/// LIMIT 1
/// ```
pub(crate) fn select_block_header_by_block_num(
    conn: &mut SqliteConnection,
    maybe_block_num: Option<BlockNumber>,
) -> Result<Option<BlockHeader>, DatabaseError> {
    let sel = SelectDsl::select(schema::block_headers::table, BlockHeaderRawRow::as_select());
    let row = if let Some(block_num) = maybe_block_num {
        sel.filter(schema::block_headers::block_num.eq(block_num.to_raw_sql()))
            .get_result::<BlockHeaderRawRow>(conn)
            .optional()?
        // invariant: only one block exists with the given block header, so the length is
        // always zero or one
    } else {
        sel.order(schema::block_headers::block_num.desc())
            .limit(1)
            .get_result::<BlockHeaderRawRow>(conn)
            .optional()?
    };
    row.map(std::convert::TryInto::try_into).transpose()
}

/// Select block headers for the given block numbers.
///
/// # Parameters
/// * `blocks`: Iterator of block numbers to retrieve
///     - Limit: 0 <= count <= 1000
///
/// # Note
///
/// Only returns the block headers that are actually present.
///
/// # Returns
///
/// A vector of [`BlockHeader`] or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT block_num, block_header
/// FROM block_headers
/// WHERE block_num IN (?1)
/// ```
pub fn select_block_headers(
    conn: &mut SqliteConnection,
    blocks: impl Iterator<Item = BlockNumber> + Send,
) -> Result<Vec<BlockHeader>, DatabaseError> {
    // The iterators are all deterministic, so is the conjunction.
    // All calling sites do it equivalently, hence the below holds.
    // <https://doc.rust-lang.org/src/core/slice/iter/macros.rs.html#195>
    // <https://doc.rust-lang.org/src/core/option.rs.html#2273>
    // And the conjunction is truthful:
    // <https://doc.rust-lang.org/src/core/iter/adapters/chain.rs.html#184>
    QueryParamBlockLimit::check(blocks.size_hint().0)?;

    let blocks = Vec::from_iter(blocks.map(SqlTypeConvert::to_raw_sql));
    let raw_block_headers =
        QueryDsl::select(schema::block_headers::table, BlockHeaderRawRow::as_select())
            .filter(schema::block_headers::block_num.eq_any(blocks))
            .load::<BlockHeaderRawRow>(conn)?;
    vec_raw_try_into(raw_block_headers)
}

/// Select all block headers from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// A vector of [`BlockHeader`] or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT block_num, block_header
/// FROM block_headers
/// ORDER BY block_num ASC
/// ```
pub fn select_all_block_headers(
    conn: &mut SqliteConnection,
) -> Result<Vec<BlockHeader>, DatabaseError> {
    let raw_block_headers =
        QueryDsl::select(schema::block_headers::table, BlockHeaderRawRow::as_select())
            .order(schema::block_headers::block_num.asc())
            .load::<BlockHeaderRawRow>(conn)?;
    vec_raw_try_into(raw_block_headers)
}

/// Select all block headers from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// A vector of [`BlockHeader`] or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT commitment
/// FROM block_headers
/// ORDER BY block_num ASC
/// ```
pub fn select_all_block_header_commitments(
    conn: &mut SqliteConnection,
) -> Result<Vec<BlockHeaderCommitment>, DatabaseError> {
    let raw_commitments =
        QueryDsl::select(schema::block_headers::table, schema::block_headers::commitment)
            .order(schema::block_headers::block_num.asc())
            .load::<Vec<u8>>(conn)?;
    let commitments =
        Result::from_iter(raw_commitments.into_iter().map(BlockHeaderCommitment::from_raw_sql))?;
    Ok(commitments)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct BlockHeaderCommitment(pub(crate) Word);

impl BlockHeaderCommitment {
    pub fn new(header: &BlockHeader) -> Self {
        Self(header.commitment())
    }
    pub fn word(self) -> Word {
        self.0
    }
}

#[derive(Debug, Clone, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = schema::block_headers)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct BlockHeaderRawRow {
    #[expect(dead_code)]
    pub block_num: i64,
    pub block_header: Vec<u8>,
    pub signature: Vec<u8>,
    pub commitment: Vec<u8>,
    #[expect(dead_code)]
    pub block_proof: Option<Vec<u8>>,
    #[expect(dead_code)]
    pub proving_inputs: Option<Vec<u8>>,
}
impl TryInto<BlockHeader> for BlockHeaderRawRow {
    type Error = DatabaseError;
    fn try_into(self) -> Result<BlockHeader, Self::Error> {
        let block_header = BlockHeader::from_raw_sql(self.block_header)?;
        // we're bust if this invariant doesn't hold
        debug_assert_eq!(
            BlockHeaderCommitment::new(&block_header),
            BlockHeaderCommitment::from_raw_sql(self.commitment)
                .expect("Database always contains valid format commitments")
        );
        Ok(block_header)
    }
}

impl TryInto<(BlockHeader, Signature)> for BlockHeaderRawRow {
    type Error = DatabaseError;
    fn try_into(self) -> Result<(BlockHeader, Signature), Self::Error> {
        let block_header = BlockHeader::read_from_bytes(&self.block_header[..])?;
        let signature = Signature::read_from_bytes(&self.signature[..])?;
        Ok((block_header, signature))
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::block_headers)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct BlockHeaderInsert {
    pub block_num: i64,
    pub block_header: Vec<u8>,
    pub signature: Vec<u8>,
    pub commitment: Vec<u8>,
    pub proving_inputs: Option<Vec<u8>>,
}

/// Insert a [`BlockHeader`] to the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// The number of affected rows.
///
/// # Note
///
/// The [`SqliteConnection`] object is not consumed. It's up to the caller to commit or rollback the
/// transaction
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
)]
pub(crate) fn insert_block_header(
    conn: &mut SqliteConnection,
    block_header: &BlockHeader,
    signature: &Signature,
    proving_inputs: Option<Vec<u8>>,
) -> Result<usize, DatabaseError> {
    let row = BlockHeaderInsert {
        block_num: block_header.block_num().to_raw_sql(),
        block_header: block_header.to_bytes(),
        signature: signature.to_bytes(),
        commitment: BlockHeaderCommitment::new(block_header).to_raw_sql(),
        proving_inputs,
    };
    let count = diesel::insert_into(schema::block_headers::table).values(&[row]).execute(conn)?;
    Ok(count)
}

/// Select the serialized proving inputs for a given block number.
///
/// # Returns
///
/// `None` if the block does not exist or has no proving inputs stored.
///
/// # Raw SQL
///
/// ```sql
/// SELECT proving_inputs
/// FROM block_headers
/// WHERE block_num = ?1
/// ```
pub(crate) fn select_block_proving_inputs(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
) -> Result<Option<Vec<u8>>, DatabaseError> {
    let inputs: Option<Option<Vec<u8>>> =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::proving_inputs)
            .filter(schema::block_headers::block_num.eq(block_num.to_raw_sql()))
            .get_result(conn)
            .optional()?;
    Ok(inputs.flatten())
}

/// Store a [`BlockProof`] for a committed block.
///
/// Updates the `block_proof` column for the row with the given `block_num`.
///
/// # Returns
///
/// The number of affected rows (expected: 1).
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    fields(block_num = %block_num),
    err,
)]
pub(crate) fn insert_block_proof(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    block_proof: &BlockProof,
) -> Result<usize, DatabaseError> {
    let count = diesel::update(
        schema::block_headers::table
            .filter(schema::block_headers::block_num.eq(block_num.to_raw_sql())),
    )
    .set(schema::block_headers::block_proof.eq(block_proof.to_bytes()))
    .execute(conn)?;
    Ok(count)
}

/// Select all block numbers that have not yet been proven, ordered ascending.
///
/// The genesis block (block 0) is excluded because it is never proven.
///
/// # Raw SQL
///
/// ```sql
/// SELECT block_num
/// FROM block_headers
/// WHERE block_proof IS NULL
///   AND block_num > 0
/// ORDER BY block_num ASC
/// ```
pub(crate) fn select_unproven_blocks(
    conn: &mut SqliteConnection,
) -> Result<Vec<BlockNumber>, DatabaseError> {
    let block_nums: Vec<i64> =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::block_num)
            .filter(schema::block_headers::block_proof.is_null())
            .filter(schema::block_headers::block_num.gt(0i64))
            .order(schema::block_headers::block_num.asc())
            .load(conn)?;
    block_nums
        .into_iter()
        .map(BlockNumber::from_raw_sql)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Select the highest block number that has been proven.
///
/// Returns `None` if no blocks have been proven yet (genesis is never proven).
///
/// # Raw SQL
///
/// ```sql
/// SELECT MAX(block_num)
/// FROM block_headers
/// WHERE block_proof IS NOT NULL
/// ```
pub(crate) fn select_latest_proven_block_num(
    conn: &mut SqliteConnection,
) -> Result<Option<BlockNumber>, DatabaseError> {
    use diesel::dsl::max;

    let block_num: Option<i64> = SelectDsl::select(
        schema::block_headers::table.filter(schema::block_headers::block_proof.is_not_null()),
        max(schema::block_headers::block_num),
    )
    .get_result(conn)?;

    block_num.map(BlockNumber::from_raw_sql).transpose().map_err(Into::into)
}

/// Select the [`BlockProof`] for a given block number, if it exists.
///
/// # Returns
///
/// `None` if the block does not exist or has not been proven yet.
///
/// # Raw SQL
///
/// ```sql
/// SELECT block_proof
/// FROM block_headers
/// WHERE block_num = ?1
/// ```
pub(crate) fn select_block_proof(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
) -> Result<Option<BlockProof>, DatabaseError> {
    let proof_bytes: Option<Option<Vec<u8>>> =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::block_proof)
            .filter(schema::block_headers::block_num.eq(block_num.to_raw_sql()))
            .get_result(conn)
            .optional()?;
    // Flatten: None (row not found) or Some(None) (proof is NULL) => None.
    match proof_bytes.flatten() {
        Some(bytes) => Ok(Some(BlockProof::read_from_bytes(&bytes[..])?)),
        None => Ok(None),
    }
}
