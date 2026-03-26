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
use miden_node_proto::BlockProofRequest;
use miden_node_utils::limiter::{QueryParamBlockLimit, QueryParamLimiter};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::utils::serde::{Deserializable, Serializable};

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
    pub proven_in_sequence: bool,
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
    proving_inputs: Option<BlockProofRequest>,
) -> Result<usize, DatabaseError> {
    // Only the genesis block should be inserted without proving inputs.
    if proving_inputs.is_none() && block_header.block_num() != BlockNumber::GENESIS {
        return Err(DatabaseError::DataCorrupted(
            "Only the genesis block should be inserted without proving inputs".into(),
        ));
    }
    // We treat the genesis as proven.
    let proven_in_sequence = proving_inputs.is_none();
    let row = BlockHeaderInsert {
        block_num: block_header.block_num().to_raw_sql(),
        block_header: block_header.to_bytes(),
        signature: signature.to_bytes(),
        commitment: BlockHeaderCommitment::new(block_header).to_raw_sql(),
        proving_inputs: proving_inputs.map(|inputs| inputs.to_bytes()),
        proven_in_sequence,
    };
    let count = diesel::insert_into(schema::block_headers::table).values(&[row]).execute(conn)?;
    Ok(count)
}

/// Select the proving inputs for a given block number.
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
) -> Result<Option<BlockProofRequest>, DatabaseError> {
    let inputs: Option<Option<Vec<u8>>> =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::proving_inputs)
            .filter(schema::block_headers::block_num.eq(block_num.to_raw_sql()))
            .get_result(conn)
            .optional()?;
    inputs
        .flatten()
        .map(|bytes| BlockProofRequest::read_from_bytes(&bytes))
        .transpose()
        .map_err(Into::into)
}

/// Mark a committed block as proven and advance the proven-in-sequence tip.
///
/// This atomically:
/// 1. Clears `proving_inputs` for the given block (marking it proven).
/// 2. Queries all blocks where `proving_inputs IS NULL AND proven_in_sequence = FALSE`.
/// 3. Walks forward from the current proven-in-sequence tip through consecutive proven blocks and
///    sets `proven_in_sequence = TRUE` for each.
///
/// Because all three steps happen within the caller's transaction, there is no window
/// where a block could be proven but not yet marked in-sequence due to interruption.
///
/// Returns [`DatabaseError::DataCorrupted`] if any proven-but-not-in-sequence block is found at
/// or below the current tip, as that indicates a consistency bug.
///
/// # Returns
///
/// The block numbers that were newly marked as proven in sequence (may be empty if the newly
/// proven block doesn't yet form a contiguous chain from the tip).
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    fields(block.number = %block_num),
    err,
)]
pub(crate) fn mark_proven_and_advance_sequence(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
) -> Result<Vec<BlockNumber>, DatabaseError> {
    // Clear proving_inputs for the specified block.
    diesel::update(
        schema::block_headers::table
            .filter(schema::block_headers::block_num.eq(block_num.to_raw_sql())),
    )
    .set(schema::block_headers::proving_inputs.eq(None::<Vec<u8>>))
    .execute(conn)?;

    // Get the current proven-in-sequence tip (highest in-sequence).
    let tip: i64 =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::block_num)
            .filter(schema::block_headers::proven_in_sequence.eq(true))
            .order(schema::block_headers::block_num.desc())
            .first(conn)?;
    let mut tip = BlockNumber::from_raw_sql(tip)?;

    // Get all blocks that are proven but not yet in-sequence.
    let unsequenced: Vec<i64> =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::block_num)
            .filter(schema::block_headers::proving_inputs.is_null())
            .filter(schema::block_headers::proven_in_sequence.eq(false))
            .order(schema::block_headers::block_num.asc())
            .load(conn)?;

    // Walk forward from the tip through consecutive proven blocks.
    let mut newly_in_sequence = Vec::new();
    for raw in unsequenced {
        let candidate = BlockNumber::from_raw_sql(raw)?;
        if candidate <= tip {
            return Err(DatabaseError::DataCorrupted(format!(
                "block {candidate} is proven but not marked in-sequence while the tip is at {tip}"
            )));
        }
        if candidate == tip + 1 {
            tip = candidate;
            newly_in_sequence.push(candidate);
        } else {
            break;
        }
    }

    // Mark the newly contiguous blocks as proven-in-sequence.
    if !newly_in_sequence.is_empty() {
        let raw_nums: Vec<i64> = newly_in_sequence.iter().map(|b| b.to_raw_sql()).collect();
        diesel::update(
            schema::block_headers::table.filter(schema::block_headers::block_num.eq_any(&raw_nums)),
        )
        .set(schema::block_headers::proven_in_sequence.eq(true))
        .execute(conn)?;
    }

    Ok(newly_in_sequence)
}

/// Select unproven block numbers greater than `after`, in ascending order, up to `limit`.
///
/// A block is unproven when its `proving_inputs` are non-NULL.
///
/// # Raw SQL
///
/// ```sql
/// SELECT block_num
/// FROM block_headers
/// WHERE proving_inputs IS NOT NULL
///   AND block_num > ?
/// ORDER BY block_num ASC
/// LIMIT ?
/// ```
pub(crate) fn select_unproven_blocks(
    conn: &mut SqliteConnection,
    after: BlockNumber,
    limit: usize,
) -> Result<Vec<BlockNumber>, DatabaseError> {
    let block_nums: Vec<i64> =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::block_num)
            .filter(schema::block_headers::proving_inputs.is_not_null())
            .filter(schema::block_headers::block_num.gt(after.to_raw_sql()))
            .order(schema::block_headers::block_num.asc())
            .limit(i64::try_from(limit).expect("unproven block number limit should fit in i64"))
            .load(conn)?;

    block_nums
        .into_iter()
        .map(BlockNumber::from_raw_sql)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Select the highest block number that has been proven in an unbroken sequence from genesis.
///
/// A block is marked `proven_in_sequence` when it and all its ancestors have been proven. This
/// is maintained by the proof scheduler as blocks complete proving (potentially out of order).
///
/// The genesis block is always inserted with `proven_in_sequence = TRUE`.
///
/// This function is expected to only ever be called after a genesis block has been inserted into
/// the database. As such, if no proven-in-sequence block is found, it is treated as an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT MAX(block_num)
/// FROM block_headers
/// WHERE proven_in_sequence = TRUE
/// ```
pub(crate) fn select_latest_proven_in_sequence_block_num(
    conn: &mut SqliteConnection,
) -> Result<BlockNumber, DatabaseError> {
    let block_num: i64 =
        SelectDsl::select(schema::block_headers::table, schema::block_headers::block_num)
            .filter(schema::block_headers::proven_in_sequence.eq(true))
            .order(schema::block_headers::block_num.desc())
            .first(conn)?;

    BlockNumber::from_raw_sql(block_num).map_err(Into::into)
}
