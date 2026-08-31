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
fn account_storage_map_details_partial_map_round_trip() {
    let slot_name = test_slot_name();
    let key0 = StorageMapKey::from_index(1);
    let key1 = StorageMapKey::from_index(2);
    let value0 = word_from_u32([1, 2, 3, 4]);
    let storage_map = StorageMap::with_entries([(key0, value0)]).unwrap();
    let proofs = vec![storage_map.open(&key0).into(), storage_map.open(&key1).into()];

    let details = AccountStorageMapDetails::from_proofs(
        slot_name,
        storage_map.root(),
        vec![key0, key1],
        proofs,
    )
    .unwrap();
    let encoded: crate::generated::rpc::account_storage_details::AccountStorageMapDetails =
        details.clone().into();
    let decoded = AccountStorageMapDetails::try_from(encoded).unwrap();

    assert_eq!(decoded, details);
    assert_matches::assert_matches!(
        decoded.entries,
        StorageMapEntries::PartialMap { map_keys, partial_smt } => {
            assert_eq!(map_keys, vec![key0, key1]);
            assert_eq!(partial_smt.get_value(&key0.hash().as_word()).unwrap(), value0);
            assert_eq!(partial_smt.get_value(&key1.hash().as_word()).unwrap(), Word::empty());
        }
    );
}

#[test]
fn account_storage_map_details_rejects_duplicate_partial_map_keys() {
    let slot_name = test_slot_name();
    let key = StorageMapKey::from_index(1);
    let storage_map = StorageMap::with_entries([(key, word_from_u32([1, 2, 3, 4]))]).unwrap();
    let proof: SmtProof = storage_map.open(&key).into();

    let err = AccountStorageMapDetails::from_proofs(
        slot_name,
        storage_map.root(),
        vec![key, key],
        vec![proof.clone(), proof],
    )
    .unwrap_err();

    assert!(err.to_string().contains("duplicate keys"));
}

#[test]
fn account_storage_map_details_rejects_missing_result() {
    let encoded = crate::generated::rpc::account_storage_details::AccountStorageMapDetails {
        slot_name: test_slot_name().to_string(),
        result: None,
    };

    let err = AccountStorageMapDetails::try_from(encoded).unwrap_err();
    assert!(err.to_string().contains("result"));
}

#[test]
fn account_storage_map_details_rejects_false_limit_marker() {
    use crate::generated::rpc::account_storage_details::account_storage_map_details::Result;

    let encoded = crate::generated::rpc::account_storage_details::AccountStorageMapDetails {
        slot_name: test_slot_name().to_string(),
        result: Some(Result::TooManyEntries(false)),
    };

    let err = AccountStorageMapDetails::try_from(encoded).unwrap_err();
    assert!(err.to_string().contains("must be true"));
}

#[test]
fn account_storage_details_rejects_partial_map_root_mismatch() {
    let slot_name = test_slot_name();
    let key = StorageMapKey::from_index(1);
    let storage_map = StorageMap::with_entries([(key, word_from_u32([1, 2, 3, 4]))]).unwrap();
    let map_details = AccountStorageMapDetails::from_proofs(
        slot_name.clone(),
        storage_map.root(),
        vec![key],
        vec![storage_map.open(&key).into()],
    )
    .unwrap();
    let header = AccountStorageHeader::new(vec![StorageSlotHeader::new(
        slot_name,
        StorageSlotType::Map,
        Word::empty(),
    )])
    .unwrap();
    let encoded: crate::generated::rpc::AccountStorageDetails =
        AccountStorageDetails { header, map_details: vec![map_details] }.into();

    let err = AccountStorageDetails::try_from(encoded).unwrap_err();
    assert!(err.to_string().contains("does not match storage header"));
}

#[test]
fn account_detail_request_converts_all_storage_maps() {
    use crate::generated::rpc::account_request::account_detail_request::StorageRequest;

    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        storage_request: Some(StorageRequest::AllStorageMaps(true)),
    };

    let request = AccountDetailRequest::try_from(request).unwrap();

    assert_eq!(request.storage_request, AccountStorageRequest::AllStorageMaps);
}

#[test]
fn account_detail_request_rejects_false_all_storage_maps() {
    use crate::generated::rpc::account_request::account_detail_request::StorageRequest;

    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        storage_request: Some(StorageRequest::AllStorageMaps(false)),
    };

    let err = AccountDetailRequest::try_from(request).unwrap_err();

    assert!(err.to_string().contains("all_storage_maps"));
}

#[test]
fn account_detail_request_converts_explicit_storage_maps() {
    use crate::generated::rpc::account_request::account_detail_request::{
        StorageMapDetailRequest,
        StorageMapDetailRequests,
        StorageRequest,
        storage_map_detail_request,
    };

    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        storage_request: Some(StorageRequest::StorageMaps(StorageMapDetailRequests {
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
fn account_detail_request_rejects_duplicate_storage_map_keys() {
    use crate::generated::rpc::account_request::account_detail_request::{
        StorageMapDetailRequest,
        StorageMapDetailRequests,
        StorageRequest,
        storage_map_detail_request,
    };
    use crate::generated::rpc::account_request::account_detail_request::storage_map_detail_request::MapKeys;

    let map_key: crate::generated::primitives::Word = Word::from([1, 2, 3, 4u32]).into();
    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        storage_request: Some(StorageRequest::StorageMaps(StorageMapDetailRequests {
            storage_maps: vec![StorageMapDetailRequest {
                slot_name: "miden::test::storage::slot".to_string(),
                slot_data: Some(storage_map_detail_request::SlotData::MapKeys(MapKeys {
                    map_keys: vec![map_key.clone(), map_key],
                })),
            }],
        })),
    };

    let err = AccountDetailRequest::try_from(request).unwrap_err();

    assert!(err.to_string().contains("duplicate keys"));
}

#[test]
fn account_detail_request_allows_no_storage_slot_data() {
    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        storage_request: None,
    };

    let request = AccountDetailRequest::try_from(request).unwrap();

    assert_eq!(request.storage_request, AccountStorageRequest::None);
}
