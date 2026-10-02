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
use miden_protocol::block::{BlockHeader, BlockNumber};

use super::DatabaseError;
use crate::db::models::conv::SqlTypeConvert;
use crate::db::{BlockHeaderCommitment, schema};

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
        // invariant: only one block exists with the given block header, so the length is always
        // zero or one
    } else {
        sel.order(schema::block_headers::block_num.desc())
            .limit(1)
            .get_result::<BlockHeaderRawRow>(conn)
            .optional()?
    };
    row.map(std::convert::TryInto::try_into).transpose()
}

#[derive(Debug, Clone, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = schema::block_headers)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct BlockHeaderRawRow {
    #[expect(dead_code)]
    pub block_num: i64,
    pub block_header: Vec<u8>,
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
