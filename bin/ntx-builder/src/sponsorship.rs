//! Detection and decoding of `FEE_SPONSORSHIP` notes.

use miden_protocol::block::BlockNumber;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteId, Nullifier};
use miden_standards::note::{FeeSponsorshipNote, FeeSponsorshipNoteStorage};

// SPONSORSHIP NOTE
// ================================================================================================

/// A committed [`Note`] validated to be a `FEE_SPONSORSHIP` note.
///
/// Sponsorship notes carry no attachments, so they are not [`AccountTargetNetworkNote`]s; they are
/// recognized purely by their script root. The note is retained exactly as observed on chain;
/// storage-derived values are re-decoded on access, which construction proves cannot fail.
#[derive(Debug, Clone)]
pub struct SponsorshipNote {
    note: Note,
}

impl SponsorshipNote {
    /// Returns the decoded `FEE_SPONSORSHIP` storage of the underlying note.
    fn storage(&self) -> FeeSponsorshipNoteStorage {
        FeeSponsorshipNoteStorage::try_from(self.note.storage().items())
            .expect("SponsorshipNote guarantees valid FEE_SPONSORSHIP storage")
    }

    /// Returns the ID of the feature note this sponsorship pays the fee for.
    pub fn feature_note_id(&self) -> NoteId {
        self.storage().feature_note_id()
    }

    /// Returns the block height at or after which the reclaimer may reclaim the note, if reclaim is
    /// enabled.
    pub fn reclaim_height(&self) -> Option<BlockNumber> {
        self.storage().reclaim_height()
    }

    /// Returns the ID of the underlying note.
    pub fn id(&self) -> NoteId {
        self.note.id()
    }

    /// Returns the nullifier of the underlying note.
    pub fn nullifier(&self) -> Nullifier {
        self.note.nullifier()
    }

    /// Returns a reference to the underlying [`Note`].
    pub fn as_note(&self) -> &Note {
        &self.note
    }
}

// TODO: Migrate to protocol's `FeeSponsorshipNote` after the merge of
// [#3746](https://github.com/0xMiden/protocol/pull/3746).
impl TryFrom<Note> for SponsorshipNote {
    type Error = NoteError;

    /// Attempts to interpret `note` as a `FEE_SPONSORSHIP` note.
    ///
    /// # Errors
    ///
    /// Returns an error if the note's script root is not the `FEE_SPONSORSHIP` script root, its
    /// note storage does not decode as `FEE_SPONSORSHIP` storage, or it does not carry exactly one
    /// asset. The note script asserts all of these itself, so a note rejected here could never be
    /// consumed as a sponsorship anyway.
    fn try_from(note: Note) -> Result<Self, Self::Error> {
        if note.script().root() != FeeSponsorshipNote::script_root() {
            return Err(NoteError::other(
                "note script root does not match the FEE_SPONSORSHIP script root",
            ));
        }
        FeeSponsorshipNoteStorage::try_from(note.storage().items())?;
        if note.assets().num_assets() != 1 {
            return Err(NoteError::other("fee sponsorship note must carry exactly one asset"));
        }
        Ok(Self { note })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::note::NoteId;

    use super::*;
    use crate::test_utils::{
        mock_network_account_id,
        mock_single_target_note,
        mock_sponsorship_note,
    };

    fn feature_note_id() -> NoteId {
        NoteId::from_raw(Word::from([7, 8, 9, 10u32]))
    }

    /// A `FEE_SPONSORSHIP` note round-trips through detection with its storage intact.
    #[test]
    fn try_from_accepts_sponsorship_note() {
        let note = mock_sponsorship_note(mock_network_account_id(), feature_note_id(), 1);

        let detected = SponsorshipNote::try_from(note.clone())
            .expect("a FEE_SPONSORSHIP note must be detected");

        assert_eq!(detected.feature_note_id(), feature_note_id());
        assert_eq!(detected.id(), note.id());
        assert_eq!(detected.nullifier(), note.nullifier());
        assert_eq!(detected.reclaim_height(), None);
    }

    /// A regular network note (different script root) is not a sponsorship.
    #[test]
    fn try_from_rejects_other_scripts() {
        let network_note = mock_single_target_note(mock_network_account_id(), 1);

        assert!(SponsorshipNote::try_from(network_note.as_note().clone()).is_err());
    }
}
