//! Note reads.
//!
//! Unspent-note queries use the pinned snapshot. Content-addressed lookups can return newer notes.

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::{Note, NoteId, NoteScript};

use super::StateView;
use crate::db::NoteRecord;
use crate::errors::DatabaseError;

impl StateView {
    /// Returns public P2ID notes that the target can consume at this view's tip.
    ///
    /// Returns at most `limit` notes in creation order. Notes spent after this view's tip remain
    /// eligible.
    pub async fn get_unspent_p2id_notes(
        &self,
        target: AccountId,
        limit: usize,
    ) -> Result<Vec<Note>, DatabaseError> {
        self.db
            .select_unspent_p2id_notes(target, self.tip(), limit)
            .await?
            .into_iter()
            .map(|record| {
                let details = record.details.ok_or_else(|| {
                    DatabaseError::DataCorrupted("public P2ID note has no details".into())
                })?;
                let (assets, recipient) = details.into_parts();
                Ok(Note::with_attachments(
                    assets,
                    record.metadata.into_partial_metadata(),
                    recipient,
                    record.attachments,
                ))
            })
            .collect()
    }

    /// Queries a list of notes from the database.
    ///
    /// If the provided list of [`NoteId`]s is empty or no note matches, an empty list is
    /// returned. This lookup is deliberately not bounded by this view's tip (latest-wins): a note
    /// committed while a block is being applied may be returned before the snapshot advances.
    pub async fn get_notes_by_id(
        &self,
        note_ids: Vec<NoteId>,
    ) -> Result<Vec<NoteRecord>, DatabaseError> {
        self.db.select_notes_by_id(note_ids).await
    }

    /// Returns the script for a note by its root.
    pub async fn get_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, DatabaseError> {
        self.db.select_note_script_by_root(root).await
    }
}
