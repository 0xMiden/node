use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use diesel::query_dsl::methods::SelectDsl;
use diesel::{
    ExpressionMethods,
    QueryDsl,
    Queryable,
    QueryableByName,
    RunQueryDsl,
    Selectable,
    SelectableHelper,
    SqliteConnection,
};
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamLimiter,
    QueryParamNullifierLimit,
    QueryParamNullifierPrefixLimit,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;
use miden_protocol::utils::{Deserializable, Serializable};

use super::DatabaseError;
use crate::COMPONENT;
use crate::db::models::conv::{SqlTypeConvert, nullifier_prefix_to_raw_sql};
use crate::db::models::utils::{get_nullifier_prefix, vec_raw_try_into};
use crate::db::{NullifierInfo, schema};

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
/// A vector of [`NullifierInfo`] with the nullifiers and the block height at which they were
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     nullifier,
///     block_num
/// FROM
///     nullifiers
/// WHERE
///     nullifier_prefix IN (?1) AND
///     block_num >= ?2 AND
///     block_num <= ?3
/// ORDER BY
///     block_num ASC
/// LIMIT
///     ?4
/// ```
pub(crate) fn select_nullifiers_by_prefix(
    conn: &mut SqliteConnection,
    prefix_len: u8,
    nullifier_prefixes: &[u16],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<(Vec<NullifierInfo>, BlockNumber), DatabaseError> {
    // Size calculation: max 2^16 nullifiers per block × 36 bytes per nullifier = ~2.25MB
    pub const NULLIFIER_BYTES: usize = 32; // digest size (nullifier)
    pub const BLOCK_NUM_BYTES: usize = 4; // 32 bits per block number
    pub const ROW_OVERHEAD_BYTES: usize = NULLIFIER_BYTES + BLOCK_NUM_BYTES; // 36 bytes
    pub const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

    assert_eq!(prefix_len, 16, "Only 16-bit prefixes are supported");

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    QueryParamNullifierPrefixLimit::check(nullifier_prefixes.len())?;

    let prefixes = nullifier_prefixes.iter().map(|prefix| nullifier_prefix_to_raw_sql(*prefix));
    let raw = SelectDsl::select(schema::nullifiers::table, NullifierWithoutPrefixRawRow::as_select())
            .filter(schema::nullifiers::nullifier_prefix.eq_any(prefixes))
            .filter(schema::nullifiers::block_num.ge(block_range.start().to_raw_sql()))
            .filter(schema::nullifiers::block_num.le(block_range.end().to_raw_sql()))
            .order(schema::nullifiers::block_num.asc())
            // Request an additional row so we can determine whether this is the last page.
            .limit(i64::try_from(MAX_ROWS + 1).expect("limit fits within i64"))
            .load::<NullifierWithoutPrefixRawRow>(conn)?;

    // Discard the last block in the response (assumes more than one block may be present)
    if let Some(last) = raw.last()
        && raw.len() > MAX_ROWS
    {
        let last_block_num_i64 = last.block_num;

        let nullifiers = vec_raw_try_into(
            raw.into_iter().take_while(|row| row.block_num != last_block_num_i64),
        )?;

        let last_block_included = BlockNumber::from_raw_sql(last_block_num_i64.saturating_sub(1))?;

        Ok((nullifiers, last_block_included))
    } else {
        Ok((vec_raw_try_into(raw)?, *block_range.end()))
    }
}

/// Select all nullifiers from the DB
///
/// # Returns
///
/// A vector with nullifiers and the block height at which they were created, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     nullifier,
///     block_num
/// FROM
///     nullifiers
/// ORDER BY
///     block_num ASC
/// ```
#[cfg(test)]
pub(crate) fn select_all_nullifiers(
    conn: &mut SqliteConnection,
) -> Result<Vec<NullifierInfo>, DatabaseError> {
    let nullifiers_raw =
        SelectDsl::select(schema::nullifiers::table, NullifierWithoutPrefixRawRow::as_select())
            .load::<NullifierWithoutPrefixRawRow>(conn)?;
    vec_raw_try_into(nullifiers_raw)
}

/// Page of nullifiers returned by [`select_nullifiers_paged`].
#[derive(Debug)]
pub struct NullifiersPage {
    /// The nullifiers in this page.
    pub nullifiers: Vec<NullifierInfo>,
    /// If `Some`, there are more results. Use this as the `after_nullifier` for the next page.
    pub next_cursor: Option<Nullifier>,
}

/// Selects nullifiers with pagination.
///
/// Returns up to `page_size` nullifiers, starting after `after_nullifier` if provided.
/// Results are ordered by nullifier bytes for stable pagination.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     nullifier,
///     block_num
/// FROM
///     nullifiers
/// WHERE
///     (nullifier > :after_nullifier OR :after_nullifier IS NULL)
/// ORDER BY
///     nullifier ASC
/// LIMIT :page_size + 1
/// ```
pub(crate) fn select_nullifiers_paged(
    conn: &mut SqliteConnection,
    page_size: NonZeroUsize,
    after_nullifier: Option<Nullifier>,
) -> Result<NullifiersPage, DatabaseError> {
    // Fetch one extra to determine if there are more results
    #[allow(clippy::cast_possible_wrap)]
    let limit = (page_size.get() + 1) as i64;

    let mut query =
        SelectDsl::select(schema::nullifiers::table, NullifierWithoutPrefixRawRow::as_select())
            .order_by(schema::nullifiers::nullifier.asc())
            .limit(limit)
            .into_boxed();

    if let Some(cursor) = after_nullifier {
        query = query.filter(schema::nullifiers::nullifier.gt(cursor.to_bytes()));
    }

    let nullifiers_raw = query.load::<NullifierWithoutPrefixRawRow>(conn)?;
    let mut nullifiers: Vec<NullifierInfo> = vec_raw_try_into(nullifiers_raw)?;

    // If we got more than page_size, there are more results
    let next_cursor = if nullifiers.len() > page_size.get() {
        nullifiers.pop(); // Remove the extra element
        nullifiers.last().map(|info| info.nullifier)
    } else {
        None
    };

    Ok(NullifiersPage { nullifiers, next_cursor })
}

/// Insert nullifiers for a block into the database.
///
/// # Parameters
/// * `nullifiers`: List of nullifiers to insert
///     - Limit: 0 <= count <= 1000
/// * `block_num`: Block number to associate with the nullifiers
///
/// # Returns
///
/// The number of affected rows.
///
/// # Note
///
/// The [`SqliteConnection`] object is not consumed. It's up to the caller to commit or rollback the
/// transaction.
///
/// # Raw SQL
///
/// ```sql
/// UPDATE notes
/// SET consumed_at = ?1
/// WHERE nullifier IN (?2);
///
/// INSERT INTO nullifiers (nullifier, nullifier_prefix, block_num)
/// VALUES (?1, ?2, ?3)
/// ```
#[allow(clippy::too_many_lines)]
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
)]
pub(crate) fn insert_nullifiers_for_block(
    conn: &mut SqliteConnection,
    nullifiers: &[Nullifier],
    block_num: BlockNumber,
) -> Result<usize, DatabaseError> {
    QueryParamNullifierLimit::check(nullifiers.len())?;
    let serialized_nullifiers =
        Vec::<Vec<u8>>::from_iter(nullifiers.iter().map(Nullifier::to_bytes));

    let mut count = diesel::update(schema::notes::table)
        .filter(schema::notes::nullifier.eq_any(&serialized_nullifiers))
        .set(schema::notes::consumed_at.eq(Some(block_num.to_raw_sql())))
        .execute(conn)?;

    count += diesel::insert_into(schema::nullifiers::table)
        .values(Vec::from_iter(nullifiers.iter().zip(serialized_nullifiers.iter()).map(
            |(nullifier, bytes)| {
                (
                    schema::nullifiers::nullifier.eq(bytes),
                    schema::nullifiers::nullifier_prefix
                        .eq(nullifier_prefix_to_raw_sql(get_nullifier_prefix(nullifier))),
                    schema::nullifiers::block_num.eq(block_num.to_raw_sql()),
                )
            },
        )))
        .execute(conn)?;

    Ok(count)
}

#[derive(Debug, Clone, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = schema::nullifiers)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NullifierWithoutPrefixRawRow {
    pub nullifier: Vec<u8>,
    pub block_num: i64,
}

impl TryInto<NullifierInfo> for NullifierWithoutPrefixRawRow {
    type Error = DatabaseError;
    fn try_into(self) -> Result<NullifierInfo, Self::Error> {
        let nullifier = Nullifier::read_from_bytes(&self.nullifier)?;
        let block_num = BlockNumber::from_raw_sql(self.block_num)?;
        Ok(NullifierInfo { nullifier, block_num })
    }
}
