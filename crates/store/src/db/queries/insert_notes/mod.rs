//! Inserts the notes created by a block.

use miden_node_db::sqlite::{DbValue, ToSqlValue, WriteTx};
use miden_node_tracing::miden_instrument;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteAssets, NoteDetails, NoteStorage, Nullifier};
use miden_standards::note::NetworkAccountTarget;

use crate::COMPONENT;
use crate::db::NoteRecord;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("insert_note.sql");

// NETWORK NOTE TYPE
// ================================================================================================

/// Classifies network notes for database storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub(crate) enum NetworkNoteType {
    /// Not a network note.
    None = 0,
    /// Single account target network note (has `NetworkAccountTarget` attachment).
    SingleTarget = 1,
}

impl ToSqlValue for NetworkNoteType {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(*self as i64)
    }
}

// QUERY
// ================================================================================================

/// Inserts the notes created by a block. Public notes are inserted with their nullifier.
///
/// # Returns
///
/// The number of affected rows.
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub(crate) fn insert_notes(
    tx: &WriteTx<'_>,
    notes: &[(NoteRecord, Option<Nullifier>)],
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    for (note, nullifier) in notes {
        count += insert_note(tx, note, *nullifier)?;
    }
    Ok(count)
}

/// Inserts a single note, deriving its network-note classification from its attachments.
fn insert_note(
    tx: &WriteTx<'_>,
    note: &NoteRecord,
    nullifier: Option<Nullifier>,
) -> Result<usize, DatabaseError> {
    let target_account_id: Option<AccountId> = NetworkAccountTarget::try_from(&note.attachments)
        .ok()
        .map(|target| target.target_id());
    // A private note is never routed to a network account, even when it carries the attachment.
    let network_note_type = if target_account_id.is_some() && !note.metadata.is_private() {
        NetworkNoteType::SingleTarget
    } else {
        NetworkNoteType::None
    };

    let batch_index = index_column(note.note_index.batch_idx());
    let note_index = index_column(note.note_index.note_idx_in_batch());
    let note_type = note.metadata.note_type() as u8;

    // Private notes carry no details, in which case every detail column is NULL.
    let details = note.details.as_ref();
    let assets: Option<&NoteAssets> = details.map(NoteDetails::assets);
    let storage: Option<&NoteStorage> = details.map(NoteDetails::storage);
    // The column stores the script root as its word representation.
    let script_root: Option<Word> = details.map(|d| Word::from(d.script().root()));
    let serial_num: Option<Word> = details.map(NoteDetails::serial_num);

    Ok(tx.execute(
        SQL,
        &[
            &note.block_num,
            &batch_index,
            &note_index,
            &note.note_id,
            &note_type,
            &note.metadata.sender(),
            &note.metadata.tag(),
            &network_note_type,
            &target_account_id,
            &note.attachments,
            &note.inclusion_path,
            // New notes are always unconsumed.
            &None::<BlockNumber>,
            &nullifier,
            &assets,
            &storage,
            &script_root,
            &serial_num,
        ],
    )?)
}

/// Narrows a note index to the `u32` the column stores.
///
/// Both indices are bounded by the block's batch and note limits, which are far below `u32::MAX`.
fn index_column(index: usize) -> u32 {
    u32::try_from(index).expect("note indices are bounded well below u32::MAX")
}
