//! Row mapping shared by the `accounts` queries.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::Row;
use miden_node_proto::domain::account::AccountSummary;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

/// Maps a `SELECT account_id, account_commitment, block_num` row to an [`AccountSummary`].
pub(super) fn account_summary_from_row(row: &Row<'_>) -> Result<AccountSummary, DatabaseError> {
    Ok(AccountSummary {
        account_id: row.get::<AccountId>(0)?,
        account_commitment: row.get::<Word>(1)?,
        block_num: row.get::<BlockNumber>(2)?,
    })
}
