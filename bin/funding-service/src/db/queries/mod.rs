//! Typed funding database queries.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_db::sqlite::Row;
use miden_protocol::transaction::TransactionId;

use crate::db::{Delivery, StoredRequest};

mod insert_database_identity;
pub use insert_database_identity::insert_database_identity;

mod select_database_identity;
pub use select_database_identity::select_database_identity;

mod insert_request;
pub use insert_request::insert_request;

mod select_request;
pub use select_request::select_request;

mod select_pending_requests;
pub use select_pending_requests::select_pending_requests;

mod update_request_delivery;
pub use update_request_delivery::update_request_delivery;

fn read_request(row: &Row<'_>) -> Result<StoredRequest, DatabaseError> {
    let transaction_id: Option<TransactionId> = row.get(3)?;
    let delivery = transaction_id
        .map(|transaction_id| {
            Ok::<_, DatabaseError>(Delivery {
                transaction_id,
                committed_in_block: row.get(4)?,
                confirmed_at: read_timestamp(row, 5)?,
            })
        })
        .transpose()?;
    Ok(StoredRequest {
        sequence: row.get(0)?,
        note: row.get(1)?,
        accepted_at: read_timestamp(row, 2)?,
        delivery,
    })
}

/// Encodes a local timestamp at the database's microsecond precision.
fn timestamp_micros(timestamp: SystemTime) -> anyhow::Result<i64> {
    let elapsed = timestamp.duration_since(UNIX_EPOCH).context("clock precedes Unix epoch")?;
    i64::try_from(elapsed.as_micros()).context("timestamp exceeds i64")
}

/// Decodes a timestamp without accepting negative values or overflowing the platform's time range.
fn read_timestamp(row: &Row<'_>, column: usize) -> Result<SystemTime, DatabaseError> {
    let micros = u64::try_from(row.get::<i64>(column)?)
        .map_err(|err| DatabaseError::deserialization("SystemTime", err))?;
    UNIX_EPOCH.checked_add(Duration::from_micros(micros)).ok_or_else(|| {
        DatabaseError::deserialization(
            "SystemTime",
            std::io::Error::other("timestamp exceeds SystemTime range"),
        )
    })
}
