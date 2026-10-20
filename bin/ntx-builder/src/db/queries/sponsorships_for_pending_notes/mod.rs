//! Selects the unconsumed `FEE_SPONSORSHIP` notes bound to an account's pending feature notes.

use std::collections::HashMap;

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::account::AccountId;
use miden_protocol::note::{Note, NoteId};

const SQL: &str = include_str!("sponsorships_for_pending_notes.sql");

/// Returns the unconsumed `FEE_SPONSORSHIP` notes bound to the given account's unconsumed feature
/// notes, grouped by feature note id.
pub fn select_sponsorships_for_pending_notes(
    tx: &ReadTx<'_>,
    account_id: AccountId,
) -> Result<HashMap<NoteId, Vec<Note>>, DatabaseError> {
    let rows =
        tx.query(SQL, &[&account_id], |row| Ok((row.get::<NoteId>(0)?, row.get::<Note>(1)?)))?;

    let mut sponsorships: HashMap<NoteId, Vec<Note>> = HashMap::new();
    for (feature_note_id, note) in rows {
        sponsorships.entry(feature_note_id).or_default().push(note);
    }
    Ok(sponsorships)
}
