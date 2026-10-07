//! Row mapping shared by the `notes` queries.
//!
//! The `notes` queries select their columns in one of two fixed orders. The sync record order is
//! described at [`note_sync_record_from_row`]. The full record order is described at
//! [`note_record_from_row`]. It adds the detail columns and the joined script.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::Row;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockNoteIndex, BlockNumber};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    NoteAssets,
    NoteAttachments,
    NoteDetails,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};

use crate::db::{NoteRecord, NoteSyncRecord};

/// Maps a row that selects `committed_at, batch_index, note_index, note_id, note_type, sender, tag,
/// attachment, inclusion_path` to a [`NoteSyncRecord`].
pub(super) fn note_sync_record_from_row(row: &Row<'_>) -> Result<NoteSyncRecord, DatabaseError> {
    let (metadata, attachments) = note_metadata_from_row(row, 4)?;

    Ok(NoteSyncRecord {
        block_num: row.get::<BlockNumber>(0)?,
        note_index: block_note_index_from_row(row, 1)?,
        note_id: NoteId::from_raw(row.get::<Word>(3)?),
        metadata,
        attachments,
        inclusion_path: row.get::<SparseMerklePath>(8)?,
    })
}

/// Maps a row that selects `committed_at, batch_index, note_index, note_id, note_type, sender, tag,
/// attachment, assets, storage, serial_num, inclusion_path, script` to a [`NoteRecord`].
///
/// The `script` column comes from a left join on `note_scripts`, so it can be NULL. The detail
/// columns can also be NULL. A note has details only if all of them are present.
pub(super) fn note_record_from_row(row: &Row<'_>) -> Result<NoteRecord, DatabaseError> {
    let (metadata, attachments) = note_metadata_from_row(row, 4)?;
    let details = note_details_from_row(row, 8)?;

    Ok(NoteRecord {
        block_num: row.get::<BlockNumber>(0)?,
        note_index: block_note_index_from_row(row, 1)?,
        note_id: row.get::<Word>(3)?,
        metadata,
        details,
        attachments,
        inclusion_path: row.get::<SparseMerklePath>(11)?,
    })
}

/// Maps the `note_type, sender, tag, attachment` columns that start at `offset` to the note
/// metadata.
fn note_metadata_from_row(
    row: &Row<'_>,
    offset: usize,
) -> Result<(NoteMetadata, NoteAttachments), DatabaseError> {
    let note_type = NoteType::try_from(row.get::<u8>(offset)?)
        .map_err(DatabaseError::conversiont_from_sql::<NoteType, _, _>)?;
    let sender = row.get::<AccountId>(offset + 1)?;
    let tag = row.get::<NoteTag>(offset + 2)?;
    let attachments = row.get::<NoteAttachments>(offset + 3)?;

    let partial = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
    Ok((NoteMetadata::new(partial, &attachments), attachments))
}

/// Maps the `batch_index, note_index` columns that start at `offset` to a [`BlockNoteIndex`].
fn block_note_index_from_row(
    row: &Row<'_>,
    offset: usize,
) -> Result<BlockNoteIndex, DatabaseError> {
    let batch_index = row.get::<u32>(offset)? as usize;
    let note_index = row.get::<u32>(offset + 1)? as usize;

    BlockNoteIndex::new(batch_index, note_index).ok_or_else(|| {
        DatabaseError::conversiont_from_sql::<BlockNoteIndex, DatabaseError, _>(None)
    })
}

/// Maps the `assets, storage, serial_num` columns that start at `offset`, and the joined `script`
/// column, to the note details.
///
/// Private notes store none of these columns. For them, the function returns `None`.
fn note_details_from_row(
    row: &Row<'_>,
    offset: usize,
) -> Result<Option<NoteDetails>, DatabaseError> {
    let assets = row.get::<Option<NoteAssets>>(offset)?;
    let storage = row.get::<Option<NoteStorage>>(offset + 1)?;
    let serial_num = row.get::<Option<Word>>(offset + 2)?;
    // The `inclusion_path` column is between `serial_num` and `script`.
    let script = row.get::<Option<NoteScript>>(offset + 4)?;

    let (Some(assets), Some(storage), Some(serial_num)) = (assets, storage, serial_num) else {
        return Ok(None);
    };
    // A note with details must have a stored script.
    let script = script.ok_or_else(|| {
        DatabaseError::conversiont_from_sql::<NoteRecipient, DatabaseError, _>(None)
    })?;

    let recipient = NoteRecipient::new(serial_num, script, storage);
    Ok(Some(NoteDetails::new(assets, recipient)))
}
