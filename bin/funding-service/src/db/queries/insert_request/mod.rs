use std::time::SystemTime;

use miden_node_db::sqlite::WriteTx;
use miden_protocol::note::Note;

use super::timestamp_micros;

/// Inserts a funding note with its acceptance time. SQLite assigns its sequence.
pub fn insert_request(
    tx: &WriteTx<'_>,
    note: &Note,
    accepted_at: SystemTime,
) -> anyhow::Result<()> {
    tx.execute(
        include_str!("insert_request.sql"),
        &[&note.id(), note, &timestamp_micros(accepted_at)?],
    )?;
    Ok(())
}
