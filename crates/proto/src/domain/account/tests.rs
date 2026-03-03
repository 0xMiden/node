use miden_protocol::account::StorageMapKey;

use super::*;

fn word_from_u32(arr: [u32; 4]) -> Word {
    Word::from(arr)
}

fn key_from_u32(arr: [u32; 4]) -> StorageMapKey {
    StorageMapKey::new(Word::from(arr))
}

fn test_slot_name() -> StorageSlotName {
    StorageSlotName::new("miden::test::storage::slot").unwrap()
}

#[test]
fn account_storage_map_details_from_forest_entries() {
    let slot_name = test_slot_name();
    let entries = vec![
        (key_from_u32([1, 2, 3, 4]), word_from_u32([5, 6, 7, 8])),
        (key_from_u32([9, 10, 11, 12]), word_from_u32([13, 14, 15, 16])),
    ];

    let details = AccountStorageMapDetails::from_forest_entries(slot_name.clone(), entries.clone());

    assert_eq!(details.slot_name, slot_name);
    assert_eq!(details.entries, StorageMapEntries::AllEntries(entries));
}

#[test]
fn account_storage_map_details_from_forest_entries_limit_exceeded() {
    let slot_name = test_slot_name();
    // Create more entries than MAX_RETURN_ENTRIES
    let entries: Vec<_> = (0..=AccountStorageMapDetails::MAX_RETURN_ENTRIES)
        .map(|i| {
            let key = key_from_u32([i as u32, 0, 0, 0]);
            let value = word_from_u32([0, 0, 0, i as u32]);
            (key, value)
        })
        .collect();

    let details = AccountStorageMapDetails::from_forest_entries(slot_name.clone(), entries);

    assert_eq!(details.slot_name, slot_name);
    assert_eq!(details.entries, StorageMapEntries::LimitExceeded);
}
