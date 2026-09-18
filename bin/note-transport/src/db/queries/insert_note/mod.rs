use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

use crate::db::NewNote;

/// Inserts a note with the assigned cursor and timestamp.
pub fn insert_note(
    tx: &WriteTx<'_>,
    note: &NewNote,
    seq: i64,
    created_at: i64,
) -> Result<(), DatabaseError> {
    tx.execute(
        include_str!("insert_note.sql"),
        &[
            &seq,
            &note.header.id(),
            &note.header.metadata().tag(),
            &note.header,
            &note.details,
            &created_at,
            &note.after_block_num,
            &note.included_in_block,
        ],
    )?;
    Ok(())
}
