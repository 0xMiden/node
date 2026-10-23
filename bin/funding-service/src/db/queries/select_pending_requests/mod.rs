use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;

use super::read_request;
use crate::db::{DatabaseIdentity, StoredRequest};

/// Reads at most `limit` undelivered requests in acceptance order.
pub fn select_pending_requests(
    tx: &ReadTx<'_>,
    limit: i64,
    identity: DatabaseIdentity,
) -> Result<Vec<StoredRequest>, DatabaseError> {
    tx.query(include_str!("select_pending_requests.sql"), &[&limit], |row| {
        read_request(row, identity)
    })
}
