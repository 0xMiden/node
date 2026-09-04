use std::collections::{BTreeMap, BTreeSet};

use miden_node_tracing::{debug, miden_instrument};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountId,
    AccountUpdateDetails,
    StorageMapKey,
    StoragePatchOperation,
    StorageSlotName,
};
use miden_protocol::block::{BlockBody, BlockNumber};
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::TransactionId;

use crate::{COMPONENT, LOG_TARGET};

/// User-facing lifecycle information derived from a block before it is committed.
///
/// The information is emitted only after the block has been committed to all store state.
pub(super) struct BlockLifecycle {
    block_num: BlockNumber,
    registered_accounts: Vec<RegisteredAccount>,
    created_notes: Vec<CreatedNote>,
    consumed_notes: Vec<ConsumedNote>,
    storage_changes: Vec<StorageChange>,
}

impl BlockLifecycle {
    #[miden_instrument(
        target = COMPONENT,
        name = "block_lifecycle.from_block_body",
    )]
    pub(super) fn from_block_body(block_num: BlockNumber, body: &BlockBody) -> Self {
        let persisted_note_ids =
            body.output_notes().map(|(_, note)| note.id()).collect::<BTreeSet<_>>();

        let mut registered_accounts = Vec::new();
        let mut created_notes = Vec::new();
        let mut consumed_notes = Vec::new();

        for transaction in body.transactions().as_slice() {
            let transaction_id = transaction.id();

            if transaction.initial_state_commitment().is_empty() {
                registered_accounts.push(RegisteredAccount {
                    account_id: transaction.account_id(),
                    transaction_id,
                });
            }

            created_notes.extend(transaction.output_notes().iter().map(|header| {
                let note_id = header.id();
                CreatedNote {
                    note_id,
                    sender: header.metadata().sender(),
                    transaction_id,
                    erased: !persisted_note_ids.contains(&note_id),
                }
            }));

            consumed_notes.extend(transaction.input_notes().iter().map(|commitment| {
                ConsumedNote {
                    note_id: commitment.header().map(miden_protocol::note::NoteHeader::id),
                    nullifier: commitment.nullifier(),
                    transaction_id,
                }
            }));
        }

        let storage_changes = body.updated_accounts().iter().flat_map(storage_changes).collect();

        Self {
            block_num,
            registered_accounts,
            created_notes,
            consumed_notes,
            storage_changes,
        }
    }

    /// Returns nullifiers whose note IDs are not present in the transaction header.
    pub(super) fn unresolved_note_nullifiers(&self) -> Vec<Nullifier> {
        self.consumed_notes
            .iter()
            .filter_map(|note| note.note_id.is_none().then_some(note.nullifier))
            .collect()
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_lifecycle.emit",
    )]
    pub(super) fn emit(self, resolved_note_ids: &BTreeMap<Nullifier, NoteId>) {
        for account in self.registered_accounts {
            debug!(
                target: LOG_TARGET,
                "Account registered",
                account.id = account.account_id,
                block.number = self.block_num,
                transaction.id = account.transaction_id
            );
        }

        for note in self.created_notes {
            debug!(
                target: LOG_TARGET,
                "Note created",
                note.id = note.note_id,
                note.sender = note.sender,
                note.erased = note.erased,
                block.number = self.block_num,
                transaction.id = note.transaction_id
            );
        }

        for note in self.consumed_notes {
            let note_id = note.note_id.or_else(|| resolved_note_ids.get(&note.nullifier).copied());
            debug!(
                target: LOG_TARGET,
                "Note consumed",
                note.id = note_id,
                note.id_resolved = note_id.is_some(),
                note.nullifier = note.nullifier,
                block.number = self.block_num,
                transaction.id = note.transaction_id
            );
        }

        for change in self.storage_changes {
            change.emit(self.block_num);
        }
    }
}

/// Returns whether any subscriber is interested in user-facing lifecycle events.
pub(super) fn lifecycle_events_enabled() -> bool {
    miden_node_tracing::enabled!(target: LOG_TARGET, miden_node_tracing::Level::DEBUG)
}

struct RegisteredAccount {
    account_id: AccountId,
    transaction_id: TransactionId,
}

struct CreatedNote {
    note_id: NoteId,
    sender: AccountId,
    transaction_id: TransactionId,
    erased: bool,
}

struct ConsumedNote {
    note_id: Option<NoteId>,
    nullifier: Nullifier,
    transaction_id: TransactionId,
}

enum StorageChange {
    Value {
        account_id: AccountId,
        slot_name: StorageSlotName,
        operation: StoragePatchOperation,
        value: Option<Word>,
    },
    MapEntry {
        account_id: AccountId,
        slot_name: StorageSlotName,
        operation: StoragePatchOperation,
        key: StorageMapKey,
        value: Word,
    },
    MapSlot {
        account_id: AccountId,
        slot_name: StorageSlotName,
        operation: StoragePatchOperation,
        entries_count: usize,
    },
}

impl StorageChange {
    fn emit(self, block_num: BlockNumber) {
        match self {
            StorageChange::Value {
                account_id,
                slot_name,
                operation,
                value: Some(value),
            } => {
                debug!(
                    target: LOG_TARGET,
                    "Account storage updated",
                    account.id = account_id,
                    account.storage.slot = slot_name,
                    account.storage.kind = "value",
                    account.storage.operation = storage_operation(operation),
                    account.storage.value = value,
                    block.number = block_num
                );
            },
            StorageChange::Value {
                account_id,
                slot_name,
                operation,
                value: None,
            } => {
                debug!(
                    target: LOG_TARGET,
                    "Account storage updated",
                    account.id = account_id,
                    account.storage.slot = slot_name,
                    account.storage.kind = "value",
                    account.storage.operation = storage_operation(operation),
                    block.number = block_num
                );
            },
            StorageChange::MapEntry {
                account_id,
                slot_name,
                operation,
                key,
                value,
            } => {
                debug!(
                    target: LOG_TARGET,
                    "Account storage updated",
                    account.id = account_id,
                    account.storage.slot = slot_name,
                    account.storage.kind = "map",
                    account.storage.operation = storage_operation(operation),
                    account.storage.map.key = key,
                    account.storage.map.entry.operation =
                        if value.is_empty() { "remove" } else { "set" },
                    account.storage.value = value,
                    block.number = block_num
                );
            },
            StorageChange::MapSlot {
                account_id,
                slot_name,
                operation,
                entries_count,
            } => {
                debug!(
                    target: LOG_TARGET,
                    "Account storage updated",
                    account.id = account_id,
                    account.storage.slot = slot_name,
                    account.storage.kind = "map",
                    account.storage.operation = storage_operation(operation),
                    account.storage.map.entries.count = entries_count,
                    block.number = block_num
                );
            },
        }
    }
}

fn storage_changes(update: &miden_protocol::block::BlockAccountUpdate) -> Vec<StorageChange> {
    let AccountUpdateDetails::Public(patch) = update.details() else {
        return Vec::new();
    };

    let account_id = update.account_id();
    let mut changes = Vec::with_capacity(patch.storage().num_slots());

    changes.extend(patch.storage().values().map(|(slot_name, value_patch)| StorageChange::Value {
        account_id,
        slot_name: slot_name.clone(),
        operation: value_patch.patch_op(),
        value: value_patch.value(),
    }));

    for (slot_name, map_patch) in patch.storage().maps() {
        let operation = map_patch.patch_op();
        match map_patch.entries() {
            Some(entries) if !entries.is_empty() => {
                changes.extend(entries.as_map().iter().map(|(key, value)| {
                    StorageChange::MapEntry {
                        account_id,
                        slot_name: slot_name.clone(),
                        operation,
                        key: *key,
                        value: *value,
                    }
                }));
            },
            Some(entries) => {
                changes.push(StorageChange::MapSlot {
                    account_id,
                    slot_name: slot_name.clone(),
                    operation,
                    entries_count: entries.num_entries(),
                });
            },
            None => {
                changes.push(StorageChange::MapSlot {
                    account_id,
                    slot_name: slot_name.clone(),
                    operation,
                    entries_count: 0,
                });
            },
        }
    }

    changes
}

const fn storage_operation(operation: StoragePatchOperation) -> &'static str {
    match operation {
        StoragePatchOperation::Create => "create",
        StoragePatchOperation::Update => "update",
        StoragePatchOperation::Remove => "remove",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use miden_protocol::Felt;
    use miden_protocol::account::{
        AccountPatch,
        AccountStoragePatch,
        AccountVaultPatch,
        StorageMapPatch,
        StorageMapPatchEntries,
        StorageSlotPatch,
        StorageValuePatch,
    };
    use miden_protocol::block::{BlockAccountUpdate, BlockBody};
    use miden_protocol::note::{
        NoteAttachments,
        NoteDetailsCommitment,
        NoteHeader,
        NoteMetadata,
        NoteTag,
        NoteType,
        PartialNoteMetadata,
    };
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_SENDER,
    };
    use miden_protocol::transaction::{
        InputNoteCommitment,
        InputNotes,
        OrderedTransactionHeaders,
        OutputNote,
        PrivateOutputNote,
        TransactionHeader,
    };

    use super::*;

    #[test]
    fn extracts_account_and_note_lifecycle_from_transaction_headers() {
        let account_id = AccountId::try_from(ACCOUNT_ID_SENDER).unwrap();
        let persisted_header = note_header(account_id, 1);
        let erased_header = note_header(account_id, 2);
        let consumed_header = note_header(account_id, 3);
        let unresolved_nullifier = Nullifier::from_raw(word(3));
        let resolved_nullifier = Nullifier::from_raw(word(4));
        let input_notes = InputNotes::new_unchecked(vec![
            InputNoteCommitment::from(unresolved_nullifier),
            InputNoteCommitment::from_parts_unchecked(resolved_nullifier, Some(consumed_header)),
        ]);
        let transaction = TransactionHeader::new(
            account_id,
            Word::empty(),
            word(5),
            input_notes,
            vec![persisted_header, erased_header],
        )
        .expect("test transaction header should be valid");
        let transaction_id = transaction.id();
        let output_note = OutputNote::Private(
            PrivateOutputNote::new(persisted_header, NoteAttachments::default()).unwrap(),
        );
        let body = BlockBody::new_unchecked(
            Vec::new(),
            vec![vec![(0, output_note)]],
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(vec![transaction]),
        );

        let lifecycle = BlockLifecycle::from_block_body(BlockNumber::from(7), &body);

        assert_eq!(lifecycle.registered_accounts.len(), 1);
        assert_eq!(lifecycle.registered_accounts[0].account_id, account_id);
        assert_eq!(lifecycle.registered_accounts[0].transaction_id, transaction_id);
        assert_eq!(lifecycle.created_notes.len(), 2);
        assert!(!lifecycle.created_notes[0].erased);
        assert!(lifecycle.created_notes[1].erased);
        assert_eq!(lifecycle.consumed_notes.len(), 2);
        assert_eq!(lifecycle.consumed_notes[0].note_id, None);
        assert_eq!(lifecycle.consumed_notes[1].note_id, Some(consumed_header.id()));
        assert_eq!(lifecycle.unresolved_note_nullifiers(), vec![unresolved_nullifier],);
    }

    #[test]
    fn extracts_public_storage_changes() {
        let account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let value_slot = StorageSlotName::mock(1);
        let map_slot = StorageSlotName::mock(2);
        let map_key = StorageMapKey::from_index(3);
        let value = word(9);
        let map_entries = StorageMapPatchEntries::from_raw(BTreeMap::from([(map_key, value)]));
        let storage = AccountStoragePatch::from_raw(BTreeMap::from([
            (value_slot.clone(), StorageSlotPatch::Value(StorageValuePatch::Update { value })),
            (
                map_slot.clone(),
                StorageSlotPatch::Map(StorageMapPatch::Update { entries: map_entries }),
            ),
        ]))
        .unwrap();
        let patch = AccountPatch::new(
            account_id,
            storage,
            AccountVaultPatch::default(),
            None,
            Some(Felt::new_unchecked(2)),
        )
        .unwrap();
        let update =
            BlockAccountUpdate::new(account_id, word(10), AccountUpdateDetails::Public(patch))
                .expect("test account update should be valid");
        let body = BlockBody::new_unchecked(
            vec![update],
            Vec::new(),
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(Vec::new()),
        );

        let lifecycle = BlockLifecycle::from_block_body(BlockNumber::from(7), &body);

        assert_eq!(lifecycle.storage_changes.len(), 2);
        assert!(matches!(
            &lifecycle.storage_changes[0],
            StorageChange::Value {
                account_id: actual_account_id,
                slot_name,
                operation: StoragePatchOperation::Update,
                value: Some(actual_value),
            } if *actual_account_id == account_id
                && *slot_name == value_slot
                && *actual_value == value
        ));
        assert!(matches!(
            &lifecycle.storage_changes[1],
            StorageChange::MapEntry {
                account_id: actual_account_id,
                slot_name,
                operation: StoragePatchOperation::Update,
                key,
                value: actual_value,
            } if *actual_account_id == account_id
                && *slot_name == map_slot
                && *key == map_key
                && *actual_value == value
        ));
    }

    fn note_header(sender: AccountId, value: u32) -> NoteHeader {
        NoteHeader::new(
            NoteDetailsCommitment::from_raw(word(value)),
            NoteMetadata::new(
                PartialNoteMetadata::new(sender, NoteType::Private).with_tag(NoteTag::new(value)),
                &NoteAttachments::default(),
            ),
        )
    }

    fn word(value: u32) -> Word {
        Word::from([value, 0, 0, 0u32])
    }
}
