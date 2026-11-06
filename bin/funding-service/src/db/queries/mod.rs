//! Typed funding database queries.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use miden_node_db::DatabaseError;
use miden_node_db::sqlite::Row;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::note::Note;
use miden_protocol::transaction::TransactionId;

use crate::db::{DatabaseIdentity, Delivery, StoredRequest};

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

mod insert_attempt;
pub use insert_attempt::insert_attempt;

mod select_attempt;
pub use select_attempt::select_attempt;

mod select_attempt_requests;
pub use select_attempt_requests::select_attempt_requests;

mod assign_request_to_attempt;
pub use assign_request_to_attempt::assign_request_to_attempt;

mod delete_attempt;
pub use delete_attempt::delete_attempt;

mod select_deposit_sync;
pub use select_deposit_sync::select_deposit_sync;

mod update_deposit_sync;
pub use update_deposit_sync::update_deposit_sync;

#[cfg(test)]
mod select_deposits;
#[cfg(test)]
pub use select_deposits::select_deposits;

mod select_largest_deposits;
pub use select_largest_deposits::select_largest_deposits;

mod count_deposits;
pub use count_deposits::count_deposits;

mod insert_deposit;
pub use insert_deposit::insert_deposit;

mod delete_deposit;
pub use delete_deposit::delete_deposit;

mod assign_deposit_to_attempt;
pub use assign_deposit_to_attempt::assign_deposit_to_attempt;

mod select_attempt_deposits;
pub use select_attempt_deposits::select_attempt_deposits;

mod delete_attempt_deposits;
pub use delete_attempt_deposits::delete_attempt_deposits;

/// Reads a stored request, reconstructing its public P2ID note and optional delivery record.
///
/// The sender and asset come from the database identity because they are shared by every request.
fn read_request(row: &Row<'_>, identity: DatabaseIdentity) -> Result<StoredRequest, DatabaseError> {
    let amount = u64::try_from(row.get::<i64>(2)?)
        .map_err(|err| DatabaseError::deserialization("funding amount", err))?;
    let note = identity.build_note(row.get(1)?, amount, row.get(3)?)?;
    let transaction_id: Option<TransactionId> = row.get(5)?;
    let delivery = transaction_id
        .map(|transaction_id| {
            Ok::<_, DatabaseError>(Delivery {
                transaction_id,
                committed_in_block: row.get(6)?,
                confirmed_at: read_timestamp(row, 7)?,
            })
        })
        .transpose()?;
    Ok(StoredRequest {
        sequence: row.get(0)?,
        note,
        accepted_at: read_timestamp(row, 4)?,
        delivery,
    })
}

/// Reads a stored deposit and checks that the funding account can consume it.
///
/// Stored deposits must target the funding account and hold only the native asset. Invalid rows
/// produce an error because silently skipping a deposit would strand its assets.
fn read_deposit(row: &Row<'_>, identity: DatabaseIdentity) -> Result<UsdcxP2Id, DatabaseError> {
    let note: Note = row.get(0)?;
    UsdcxP2Id::from_note(note, identity.fee_asset_id)
        .filter(|deposit| deposit.target() == identity.funding_account_id)
        .ok_or_else(|| {
            DatabaseError::deserialization(
                "deposit note",
                std::io::Error::other("the funding account cannot consume the stored deposit"),
            )
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
