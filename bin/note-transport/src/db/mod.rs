use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_node_tracing::{info, miden_instrument};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteDetails, NoteHeader, NoteTag};
use miden_protocol::utils::serde::Serializable;

use crate::{COMPONENT, LOG_TARGET};

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

pub const FETCH_NOTES_MAX_BYTES: usize = 3 * 1024 * 1024;
pub const FETCH_NOTES_MAX_ROWS: usize = 500;

const CLEANUP_MAX_NOTES: u32 = 10;

mod queries;

/// A validated note to insert. Storage assigns its timestamp and cursor.
#[derive(Clone, Debug)]
pub struct NewNote {
    pub header: NoteHeader,
    pub details: NoteDetails,
    pub after_block_num: Option<BlockNumber>,
}

/// A persisted note with its storage timestamp and cursor.
#[derive(Clone, Debug)]
pub struct StoredNote {
    pub header: NoteHeader,
    pub details: NoteDetails,
    /// Microseconds since the Unix epoch, assigned when storage accepts the note.
    pub created_at: i64,
    pub seq: i64,
    pub after_block_num: Option<BlockNumber>,
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
    #[error("invalid cursor")]
    InvalidCursor,
    #[error("cursor belongs to another database generation; clear the cursor and retry")]
    StaleCursor,
    #[error("{0}")]
    InvalidData(String),
}

/// A position in one database generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub nonce: u64,
    pub sequence: u64,
}

#[derive(Debug)]
pub struct FetchPage {
    pub cursor: Cursor,
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

/// Stores a validated note and removes up to ten expired notes in the same transaction. A retry
/// preserves the first record for the note ID and does not remove expired notes.
#[miden_instrument(target = COMPONENT, err)]
pub async fn store_note(
    writer: &DbWriter,
    note: NewNote,
    max_retained_bytes: NonZeroU64,
    retention_days: NonZeroU32,
) -> Result<StoreResult, StorageError> {
    writer
        .write("store_note", move |tx| {
            if queries::note_exists(tx, &note.header.id())? {
                return Ok(StoreResult::AlreadyPresent);
            }
            let metadata = queries::select_storage_metadata(tx)?;
            let seq = metadata.next_cursor;
            let retained = metadata.retained_bytes;

            let header = note.header.to_bytes();
            let note_bytes = header
                .len()
                .checked_add(note.details.to_bytes().len())
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
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| StorageError::InvalidData(err.to_string()))?;
            let now = i64::try_from(now.as_micros())
                .map_err(|err| StorageError::InvalidData(err.to_string()))?;
            let cutoff = i128::from(now) - i128::from(retention_days.get()) * 86_400_000_000;
            let cutoff = i64::try_from(cutoff).unwrap_or(i64::MIN);
            queries::insert_note(tx, &note, seq, now)?;
            let removed_bytes =
                queries::delete_notes_created_before(tx, cutoff, CLEANUP_MAX_NOTES)?;
            // Apply capacity to the state that will be committed, including reclaimed space.
            let next_retained =
                i128::from(retained) + i128::from(note_bytes) - i128::from(removed_bytes);
            if next_retained < 0 {
                return Err(StorageError::InvalidData("retained byte count underflow".into()));
            }
            let next_retained = i64::try_from(next_retained)
                .map_err(|_| StorageError::Capacity("retained byte count overflow".into()))?;
            if u64::try_from(next_retained).expect("retained byte count is nonnegative")
                > max_retained_bytes.get()
            {
                return Err(StorageError::Capacity(format!(
                    "accepting this note would exceed the {max_retained_bytes} byte limit"
                )));
            }
            queries::update_storage_metadata(tx, next_cursor, next_retained)?;
            Ok(StoreResult::Inserted)
        })
        .await
}

/// Returns one page from a single database snapshot, in cursor order.
#[miden_instrument(target = COMPONENT, err)]
pub async fn fetch_notes(
    reader: &DbReader,
    tags: Vec<u32>,
    cursor: Option<Cursor>,
) -> Result<FetchPage, StorageError> {
    let sequence = cursor.map_or(0, |cursor| cursor.sequence);
    let sequence = i64::try_from(sequence).map_err(|_| StorageError::InvalidCursor)?;
    reader
        .read("fetch_notes", move |tx| {
            let metadata = queries::select_storage_metadata(tx)?;
            if cursor.is_some_and(|cursor| cursor.nonce != metadata.nonce) {
                return Err(StorageError::StaleCursor);
            }
            queries::fetch_notes(
                tx,
                tags.into_iter().map(NoteTag::new).collect(),
                sequence,
                metadata.nonce,
            )
        })
        .await
}

/// Records the retained byte count when the service starts.
#[miden_instrument(target = COMPONENT, err)]
pub async fn record_retained_bytes(reader: &DbReader) -> Result<(), StorageError> {
    let retained = reader.read("retained_bytes", queries::select_retained_bytes).await?;
    record_storage_usage(retained);
    Ok(())
}

fn record_storage_usage(retained: i64) {
    info!(target: LOG_TARGET, "Note transport storage usage", note_transport.retained_bytes = retained);
}

#[cfg(test)]
mod tests;
