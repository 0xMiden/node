use miden_protocol::account::StorageMapKey;

use super::*;

fn word_from_u32(arr: [u32; 4]) -> Word {
    Word::from(arr)
}

fn test_slot_name() -> StorageSlotName {
    StorageSlotName::new("miden::test::storage::slot").unwrap()
}

#[test]
fn account_storage_map_details_from_forest_entries() {
    let slot_name = test_slot_name();
    let entries = vec![
        (StorageMapKey::new(word_from_u32([1, 2, 3, 4])), word_from_u32([5, 6, 7, 8])),
        (
            StorageMapKey::new(word_from_u32([9, 10, 11, 12])),
            word_from_u32([13, 14, 15, 16]),
        ),
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
            let key = StorageMapKey::from_index(i as u32);
            let value = word_from_u32([0, 0, 0, i as u32]);
            (key, value)
        })
        .collect();

    let details = AccountStorageMapDetails::from_forest_entries(slot_name.clone(), entries);

    assert_eq!(details.slot_name, slot_name);
    assert_eq!(details.entries, StorageMapEntries::LimitExceeded);
}

#[test]
fn account_detail_request_converts_all_storage_maps() {
    use crate::generated::rpc::account_request::account_detail_request::SlotData;

    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        slot_data: Some(SlotData::AllStorageMaps(true)),
    };

    let request = AccountDetailRequest::try_from(request).unwrap();

    assert_eq!(request.storage_request, AccountStorageRequest::AllStorageMaps);
}

#[test]
fn account_detail_request_rejects_false_all_storage_maps() {
    use crate::generated::rpc::account_request::account_detail_request::SlotData;

    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        slot_data: Some(SlotData::AllStorageMaps(false)),
    };

    let err = AccountDetailRequest::try_from(request).unwrap_err();

    assert!(err.to_string().contains("all_storage_maps"));
}

#[test]
fn account_detail_request_converts_explicit_storage_maps() {
    use crate::generated::rpc::account_request::account_detail_request::{
        SlotData,
        StorageMapDetailRequest,
        StorageMapDetailRequests,
        storage_map_detail_request,
    };

    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        slot_data: Some(SlotData::StorageMaps(StorageMapDetailRequests {
            storage_maps: vec![StorageMapDetailRequest {
                slot_name: "miden::test::storage::slot".to_string(),
                slot_data: Some(storage_map_detail_request::SlotData::AllEntries(true)),
            }],
        })),
    };

    let request = AccountDetailRequest::try_from(request).unwrap();

    assert!(matches!(
        request.storage_request,
        AccountStorageRequest::Explicit(ref requests) if requests.len() == 1
    ));
}

#[test]
fn account_detail_request_allows_no_storage_slot_data() {
    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        slot_data: None,
    };

    let request = AccountDetailRequest::try_from(request).unwrap();

    assert_eq!(request.storage_request, AccountStorageRequest::None);
}
