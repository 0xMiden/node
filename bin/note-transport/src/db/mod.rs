use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use miden_node_db::sqlite::{DbReader, DbWriter, InList};
use miden_node_tracing::{info, miden_instrument};
use miden_protocol::note::NoteHeader;
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::{COMPONENT, LOG_TARGET};

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

pub const FETCH_NOTES_MAX_BYTES: usize = 3 * 1024 * 1024;
pub const FETCH_NOTES_MAX_ROWS: usize = 500;

#[derive(Clone, Debug)]
pub struct StoredNote {
    pub header: NoteHeader,
    pub details: Vec<u8>,
    pub created_at: i64,
    pub seq: i64,
    pub after_block_num: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreResult {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Database(#[from] miden_node_db::DatabaseError),
    #[error("{0}")]
    Capacity(String),
    #[error("cursor exceeds SQLite range")]
    InvalidCursor,
    #[error("{0}")]
    InvalidData(String),
}

#[derive(Debug)]
pub struct FetchPage {
    pub notes: Vec<StoredNote>,
    pub has_more: bool,
}

/// Creates a database with the current schema. The path must not exist.
#[miden_instrument(target = COMPONENT, err)]
pub fn bootstrap(path: &Path) -> anyhow::Result<()> {
    migrator()?.bootstrap(path)
}

/// Applies pending migrations to an existing database.
#[miden_instrument(target = COMPONENT, err)]
pub fn migrate(path: &Path) -> anyhow::Result<()> {
    migrator()?.migrate(path)
}

/// Verifies the schema and opens the database handles.
#[miden_instrument(target = COMPONENT, err)]
pub fn load(path: &Path) -> anyhow::Result<(DbWriter, DbReader)> {
    migrator()?.verify_latest_schema(path)?;
    Ok(miden_node_db::sqlite::open(path)?)
}

/// Stores validated note bytes. A retry preserves the first record for the note ID.
#[miden_instrument(target = COMPONENT, err)]
pub async fn store_note(
    writer: &DbWriter,
    note: StoredNote,
    max_retained_bytes: u64,
) -> Result<StoreResult, StorageError> {
    let (result, retained) = writer
        .write("store_note", move |tx| {
            let id = note.header.id().as_bytes().to_vec();
            let (seq, retained) = tx
                .query(include_str!("queries/select_storage_metadata.sql"), &[], |row| {
                    Ok((row.get::<i64>(0)?, row.get::<i64>(1)?))
                })?
                .into_iter()
                .next()
                .ok_or_else(|| StorageError::InvalidData("storage metadata is missing".into()))?;
            let exists = tx
                .query(include_str!("queries/note_exists.sql"), &[&id], |row| row.get::<i64>(0))?
                [0]
                != 0;
            if exists {
                return Ok((StoreResult::AlreadyPresent, retained));
            }

            let header = note.header.to_bytes();
            let note_bytes = header
                .len()
                .checked_add(note.details.len())
                .filter(|size| *size <= FETCH_NOTES_MAX_BYTES)
                .ok_or_else(|| {
                    StorageError::Capacity(format!(
                        "note exceeds the {FETCH_NOTES_MAX_BYTES} byte fetch limit"
                    ))
                })?;
            let next_cursor = seq
                .checked_add(1)
                .ok_or_else(|| StorageError::Capacity("cursor exhausted".into()))?;
            let note_bytes = i64::try_from(note_bytes)
                .map_err(|_| StorageError::Capacity("note size overflow".into()))?;
            let next_retained = retained
                .checked_add(note_bytes)
                .ok_or_else(|| StorageError::Capacity("retained byte count overflow".into()))?;
            if u64::try_from(next_retained)
                .map_err(|_| StorageError::InvalidData("negative retained byte count".into()))?
                > max_retained_bytes
            {
                return Err(StorageError::Capacity(format!(
                    "accepting this note would exceed the {max_retained_bytes} byte limit"
                )));
            }
            tx.execute(
                include_str!("queries/update_storage_metadata.sql"),
                &[&next_cursor, &next_retained],
            )?;
            tx.execute(
                include_str!("queries/insert_note.sql"),
                &[
                    &seq,
                    &id,
                    &note.header.metadata().tag().as_u32(),
                    &header,
                    &note.details,
                    &note.created_at,
                    &note.after_block_num,
                ],
            )?;
            Ok((StoreResult::Inserted, next_retained))
        })
        .await?;
    record_storage_usage(retained);
    Ok(result)
}

/// Returns one page from a single database snapshot, in cursor order.
#[miden_instrument(target = COMPONENT, err)]
pub async fn fetch_notes(
    reader: &DbReader,
    tags: Vec<u32>,
    cursor: u64,
) -> Result<FetchPage, StorageError> {
    let cursor = i64::try_from(cursor).map_err(|_| StorageError::InvalidCursor)?;
    if tags.is_empty() {
        return Ok(FetchPage { notes: vec![], has_more: false });
    }
    reader
        .read("fetch_notes", move |tx| {
            let tags = InList::from_i64s(tags.into_iter().map(i64::from));
            // Count one extra candidate to detect a full page. Bound bytes before loading note
            // blobs.
            let rows = tx.query(
                include_str!("queries/fetch_notes.sql"),
                &[
                    &cursor,
                    &tags,
                    &(i64::try_from(FETCH_NOTES_MAX_ROWS + 1).expect("page limit fits i64")),
                    &(i64::try_from(FETCH_NOTES_MAX_BYTES).expect("byte limit fits i64")),
                    &(i64::try_from(FETCH_NOTES_MAX_ROWS).expect("page limit fits i64")),
                ],
                |row| {
                    let header_bytes: Vec<u8> = row.get(1)?;
                    let header = NoteHeader::read_from_bytes(&header_bytes).map_err(|err| {
                        miden_node_db::DatabaseError::deserialization("NoteHeader", err)
                    })?;
                    Ok((
                        StoredNote {
                            seq: row.get(0)?,
                            header,
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
            let has_more =
                candidate_count > i64::try_from(notes.len()).expect("page length fits i64");
            Ok(FetchPage { notes, has_more })
        })
        .await
}

/// Deletes a bounded number of expired notes and releases their retained bytes.
#[miden_instrument(target = COMPONENT, err)]
pub async fn cleanup(
    writer: &DbWriter,
    retention_days: u32,
    max_rows: u32,
) -> Result<u64, StorageError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| StorageError::InvalidData(err.to_string()))?;
    let now =
        i64::try_from(now.as_micros()).map_err(|err| StorageError::InvalidData(err.to_string()))?;
    let cutoff = i128::from(now) - i128::from(retention_days) * 86_400_000_000;
    let cutoff = i64::try_from(cutoff).unwrap_or(i64::MIN);
    let (removed, retained) = writer
        .write("cleanup_notes", move |tx| {
            let retained = retained_bytes(tx)?;
            let rows = tx.query(
                include_str!("queries/select_expired_notes.sql"),
                &[&cutoff, &max_rows],
                |row| Ok((row.get::<i64>(0)?, row.get::<i64>(1)?)),
            )?;
            if rows.is_empty() {
                return Ok((0, retained));
            }
            let removed_bytes = rows
                .iter()
                .try_fold(0_i64, |sum, (_, size)| sum.checked_add(*size))
                .ok_or_else(|| StorageError::InvalidData("removed byte count overflow".into()))?;
            let next_retained = retained
                .checked_sub(removed_bytes)
                .filter(|bytes| *bytes >= 0)
                .ok_or_else(|| StorageError::InvalidData("retained byte count underflow".into()))?;
            let seqs = InList::from_i64s(rows.iter().map(|(seq, _)| *seq));
            tx.execute(include_str!("queries/delete_notes.sql"), &[&seqs])?;
            tx.execute(include_str!("queries/update_retained_bytes.sql"), &[&next_retained])?;
            Ok::<_, StorageError>((rows.len() as u64, next_retained))
        })
        .await?;
    record_storage_usage(retained);
    Ok(removed)
}

/// Records the retained byte count when the service starts.
#[miden_instrument(target = COMPONENT, err)]
pub async fn record_retained_bytes(reader: &DbReader) -> Result<(), StorageError> {
    let retained = reader.read("retained_bytes", retained_bytes).await?;
    record_storage_usage(retained);
    Ok(())
}

fn retained_bytes(tx: &miden_node_db::sqlite::ReadTx<'_>) -> Result<i64, StorageError> {
    tx.query(include_str!("queries/select_retained_bytes.sql"), &[], |row| row.get::<i64>(0))?
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::InvalidData("storage metadata is missing".into()))
}

fn record_storage_usage(retained: i64) {
    info!(target: LOG_TARGET, "Note transport storage usage", note_transport.retained_bytes = retained);
}

#[cfg(test)]
mod tests;
