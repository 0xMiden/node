use miden_node_db::sqlite::{InList, ReadTx};
use miden_protocol::note::NoteTag;

use crate::db::{FETCH_NOTES_MAX_BYTES, FETCH_NOTES_MAX_ROWS, FetchPage, StorageError, StoredNote};

/// Returns a page in cursor order. Row and byte limits apply before note blobs are loaded.
pub fn fetch_notes(
    tx: &ReadTx<'_>,
    tags: Vec<NoteTag>,
    cursor: i64,
) -> Result<FetchPage, StorageError> {
    let tags = InList::from_values(tags);
    let rows = tx.query(
        include_str!("fetch_notes.sql"),
        &[
            &cursor,
            &tags,
            &i64::try_from(FETCH_NOTES_MAX_ROWS + 1).expect("page limit fits i64"),
            &i64::try_from(FETCH_NOTES_MAX_BYTES).expect("byte limit fits i64"),
            &i64::try_from(FETCH_NOTES_MAX_ROWS).expect("page limit fits i64"),
        ],
        |row| {
            Ok((
                StoredNote {
                    seq: row.get(0)?,
                    header: row.get(1)?,
                    details: row.get(2)?,
                    created_at: row.get(3)?,
                    after_block_num: row.get(4)?,
                },
                row.get::<i64>(5)?,
            ))
        },
    )?;
    let candidate_count = rows.first().map_or(0, |(_, count)| *count);
    let notes: Vec<_> = rows.into_iter().map(|(note, _)| note).collect();
    let has_more = candidate_count > i64::try_from(notes.len()).expect("page length fits i64");
    Ok(FetchPage { notes, has_more })
}
