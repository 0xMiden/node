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
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_node_utils::limiter::{QueryParamBlockLimit, QueryParamLimiter};
use miden_protocol::block::{BlockHeader, BlockNumber};
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

#[derive(Debug, Clone, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = schema::block_headers)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct BlockHeaderRawRow {
    #[allow(dead_code)]
    pub block_num: i64,
    pub block_header: Vec<u8>,
    pub signature: Vec<u8>,
}
impl TryInto<BlockHeader> for BlockHeaderRawRow {
    type Error = DatabaseError;
    fn try_into(self) -> Result<BlockHeader, Self::Error> {
        let block_header = BlockHeader::read_from_bytes(&self.block_header[..])?;
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
}
impl From<(&BlockHeader, &Signature)> for BlockHeaderInsert {
    fn from(from: (&BlockHeader, &Signature)) -> Self {
        Self {
            block_num: from.0.block_num().to_raw_sql(),
            block_header: from.0.to_bytes(),
            signature: from.1.to_bytes(),
        }
    }
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
) -> Result<usize, DatabaseError> {
    let block_header = BlockHeaderInsert::from((block_header, signature));
    let count = diesel::insert_into(schema::block_headers::table)
        .values(&[block_header])
        .execute(conn)?;
    Ok(count)
}
