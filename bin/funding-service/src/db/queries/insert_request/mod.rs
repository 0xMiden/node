use std::time::SystemTime;

use anyhow::Context;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::NoteId;

use super::timestamp_micros;

/// Inserts a funding note with its acceptance time. SQLite assigns its sequence.
pub fn insert_request(
    tx: &WriteTx<'_>,
    note_id: NoteId,
    target: AccountId,
    amount: u64,
    serial_number: Word,
    accepted_at: SystemTime,
) -> anyhow::Result<()> {
    tx.execute(
        include_str!("insert_request.sql"),
        &[
            &note_id,
            &target,
            &i64::try_from(amount).context("funding amount exceeds i64")?,
            &serial_number,
            &timestamp_micros(accepted_at)?,
        ],
    )?;
    Ok(())
}
