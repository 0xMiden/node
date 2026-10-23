use std::time::SystemTime;

use anyhow::Context;
use miden_node_db::sqlite::WriteTx;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;

use super::timestamp_micros;

/// Inserts a funding note with its acceptance time. SQLite assigns its sequence.
pub fn insert_request(
    tx: &WriteTx<'_>,
    note: &UsdcxP2Id,
    accepted_at: SystemTime,
) -> anyhow::Result<()> {
    tx.execute(
        include_str!("insert_request.sql"),
        &[
            &note.note().id(),
            &note.target(),
            &i64::try_from(note.amount()).context("funding amount exceeds i64")?,
            &note.note().recipient().serial_num(),
            &timestamp_micros(accepted_at)?,
        ],
    )?;
    Ok(())
}
