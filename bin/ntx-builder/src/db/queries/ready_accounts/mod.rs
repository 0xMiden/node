//! Selects the network accounts that are ready for a transaction attempt.

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

const SQL: &str = include_str!("ready_accounts.sql");

/// Returns up to `limit` accounts that are ready for a transaction attempt at `block_num`, the
/// longest-waiting one first.
///
/// `busy` names the accounts to skip: those with a running attempt or an in-flight transaction.
/// `priority` names the accounts to serve first; the rest are served longest-waiting first.
#[expect(clippy::cast_possible_wrap)]
pub fn ready_accounts(
    tx: &ReadTx<'_>,
    max_attempts: usize,
    block_num: BlockNumber,
    busy: &[AccountId],
    priority: &[AccountId],
    limit: usize,
) -> Result<Vec<AccountId>, DatabaseError> {
    let busy = InList::from_values(busy.iter().copied());
    let priority = InList::from_values(priority.iter().copied());
    tx.query(
        SQL,
        &[
            &(max_attempts as i64),
            &block_num.to_raw_sql(),
            &busy,
            &priority,
            &(limit as i64),
        ],
        |row| row.get::<AccountId>(0),
    )
}
