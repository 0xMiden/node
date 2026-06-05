use std::fmt;

use miden_protocol::account::Account;
use miden_protocol::note::{NoteScriptRoot, Nullifier};
use miden_standards::account::auth::{
    NetworkAccountNoteAllowlist,
    NetworkAccountNoteAllowlistError,
};
use miden_standards::note::AccountTargetNetworkNote;

/// Notes partitioned by the target account's note-script allowlist.
pub struct PartitionedNotes {
    pub allowed: Vec<AccountTargetNetworkNote>,
    pub rejected: Vec<(Nullifier, NoteScriptRoot)>,
}

/// Returned when a note is addressed to a network account but its script root is not allowlisted by
/// that account.
#[derive(Debug, Clone)]
pub struct NoteScriptNotAllowlisted {
    script_root: NoteScriptRoot,
}

impl NoteScriptNotAllowlisted {
    pub fn new(script_root: NoteScriptRoot) -> Self {
        Self { script_root }
    }
}

impl fmt::Display for NoteScriptNotAllowlisted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "note script root {} is not allowlisted by the target network account",
            self.script_root,
        )
    }
}

impl std::error::Error for NoteScriptNotAllowlisted {}

/// Splits notes into the notes allowed by the account's note-script allowlist and rejected note
/// nullifiers paired with the offending script root.
pub fn partition_by_allowlist(
    account: &Account,
    notes: Vec<AccountTargetNetworkNote>,
) -> Result<PartitionedNotes, NetworkAccountNoteAllowlistError> {
    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())?;
    let allowed_roots = allowlist.allowed_script_roots();

    let mut allowed = Vec::with_capacity(notes.len());
    let mut rejected = Vec::new();

    for note in notes {
        let script_root = note.as_note().script().root();
        if allowed_roots.contains(&script_root) {
            allowed.push(note);
        } else {
            rejected.push((note.as_note().nullifier(), script_root));
        }
    }

    Ok(PartitionedNotes { allowed, rejected })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccountNoteAllowlistError};

    use super::*;
    use crate::test_utils::{
        mock_account,
        mock_account_with_auth_component,
        mock_network_account_id,
        mock_single_target_note,
        mock_single_target_note_with_code,
    };

    const OTHER_NOTE_SCRIPT: &str = "\
@note_script
pub proc main
    push.1 drop
end";

    #[test]
    fn partition_keeps_allowlisted_note() {
        let account_id = mock_network_account_id();
        let note = mock_single_target_note(account_id, 10);
        let root = note.as_note().script().root();
        let account = mock_account_with_auth_component(
            AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter([root]))
                .expect("non-empty allowlist should construct"),
        );

        let partitioned_notes =
            partition_by_allowlist(&account, vec![note.clone()]).expect("allowlist should load");

        assert_eq!(partitioned_notes.allowed.len(), 1);
        assert_eq!(partitioned_notes.allowed[0].as_note().nullifier(), note.as_note().nullifier());
        assert!(partitioned_notes.rejected.is_empty());
    }

    #[test]
    fn partition_rejects_non_allowlisted_note() {
        let account_id = mock_network_account_id();
        let allowed_note = mock_single_target_note(account_id, 10);
        let rejected_note =
            mock_single_target_note_with_code(account_id, 20, Some(OTHER_NOTE_SCRIPT));
        let allowed_root = allowed_note.as_note().script().root();
        let rejected_root = rejected_note.as_note().script().root();
        assert_ne!(allowed_root, rejected_root);

        let account = mock_account_with_auth_component(
            AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter([allowed_root]))
                .expect("non-empty allowlist should construct"),
        );

        let partitioned_notes = partition_by_allowlist(&account, vec![rejected_note.clone()])
            .expect("allowlist should load");

        assert!(partitioned_notes.allowed.is_empty());
        assert_eq!(
            partitioned_notes.rejected,
            vec![(rejected_note.as_note().nullifier(), rejected_root)]
        );
    }

    #[test]
    fn partition_handles_mixed_notes() {
        let account_id = mock_network_account_id();
        let allowed_note = mock_single_target_note(account_id, 10);
        let rejected_note =
            mock_single_target_note_with_code(account_id, 20, Some(OTHER_NOTE_SCRIPT));
        let allowed_root = allowed_note.as_note().script().root();
        let rejected_root = rejected_note.as_note().script().root();
        assert_ne!(allowed_root, rejected_root);

        let account = mock_account_with_auth_component(
            AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter([allowed_root]))
                .expect("non-empty allowlist should construct"),
        );

        let partitioned_notes =
            partition_by_allowlist(&account, vec![allowed_note.clone(), rejected_note.clone()])
                .expect("allowlist should load");

        assert_eq!(partitioned_notes.allowed.len(), 1);
        assert_eq!(
            partitioned_notes.allowed[0].as_note().nullifier(),
            allowed_note.as_note().nullifier()
        );
        assert_eq!(
            partitioned_notes.rejected,
            vec![(rejected_note.as_note().nullifier(), rejected_root)]
        );
    }

    #[test]
    fn partition_errors_when_allowlist_slot_is_missing() {
        let account = mock_account(mock_network_account_id());

        let result = partition_by_allowlist(&account, Vec::new());

        assert!(matches!(result, Err(NetworkAccountNoteAllowlistError::SlotNotFound)));
    }
}
