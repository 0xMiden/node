use miden_protocol::Felt;
use miden_protocol::account::{AccountIdVersion, AccountType, AssetCallbackFlag, StorageMapKey};
use miden_protocol::block::account_tree::AccountTree;

use super::*;
use crate::Verify;

#[test]
fn registration_request_debug_hides_invitation_code() {
    let code = "private invitation code";
    let account_id = AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    let request = proto::rpc::RegisterAccountRequest {
        invitation_code: code.to_owned(),
        account_id: Some(account_id.into()),
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains(code));

    let decoded = request.decode_fields().unwrap();
    assert!(!format!("{decoded:?}").contains(code));
    let verified = decoded.verify().unwrap();
    assert!(!format!("{verified:?}").contains(code));
    assert_eq!(verified.invitation_code, code);
    assert_eq!(verified.account_id, account_id);
}

fn word_from_u32(arr: [u32; 4]) -> Word {
    Word::from(arr)
}

fn test_slot_name() -> StorageSlotName {
    StorageSlotName::new("miden::test::storage::slot").unwrap()
}

fn account_response() -> proto::rpc::AccountResponse {
    let id = AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    let code = AccountCode::mock();
    let storage = AccountStorageHeader::new(vec![StorageSlotHeader::new(
        test_slot_name(),
        StorageSlotType::Value,
        Word::from([1u32, 2, 3, 4]),
    )])
    .unwrap();
    let header = AccountHeader::new(
        id,
        Felt::ONE,
        Word::empty(),
        storage.to_commitment(),
        code.commitment(),
    );
    let witness = AccountTree::with_entries([(id, header.to_commitment())]).unwrap().open(id);
    AccountResponse {
        block_num: BlockNumber::from(1),
        witness,
        details: Some(AccountDetails {
            account_header: header,
            account_code: Some(code),
            vault_details: AccountVaultDetails::Assets(Vec::new()),
            storage_details: AccountStorageDetails { header: storage, map_details: Vec::new() },
        }),
    }
    .into()
}

#[test]
fn account_response_accepts_matching_details_and_omitted_optional_data() {
    let response = account_response();
    for include_code in [true, false] {
        let mut message = response.clone();
        if !include_code {
            message.details.as_mut().unwrap().code = None;
        }
        let decoded = message.decode_fields().and_then(Verify::verify).unwrap();
        let details = decoded.details.unwrap();
        assert_eq!(details.account_code.is_some(), include_code);
        assert_eq!(details.account_header.id(), decoded.witness.id());
        assert_eq!(details.account_header.to_commitment(), decoded.witness.state_commitment());
    }

    let message = proto::rpc::AccountResponse { details: None, ..response };
    assert!(message.decode_fields().and_then(Verify::verify).unwrap().details.is_none());
}

#[test]
fn account_response_rejects_storage_that_does_not_match_header() {
    let mut message = account_response();
    message.details.as_mut().unwrap().storage_details.as_mut().unwrap().header =
        Some(AccountStorageHeader::new(Vec::new()).unwrap().into());

    let error = message.decode_fields().and_then(Verify::verify).err().unwrap();
    assert!(error.to_string().starts_with("details.storage_details.header:"), "{error}");
    assert!(error.to_string().contains("storage commitment does not match"), "{error}");
}

#[test]
fn account_response_rejects_code_that_does_not_match_header() {
    let mut message = account_response();
    message.details.as_mut().unwrap().header.as_mut().unwrap().code_commitment =
        Some(Word::empty().into());

    let error = message.decode_fields().and_then(Verify::verify).err().unwrap();
    assert!(error.to_string().starts_with("details.code:"), "{error}");
    assert!(error.to_string().contains("code commitment does not match"), "{error}");
}

#[test]
fn account_response_rejects_details_for_another_account() {
    let mut message = account_response();
    let other_id = AccountId::dummy(
        [8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    message.details.as_mut().unwrap().header.as_mut().unwrap().account_id = Some(other_id.into());

    let error = message.decode_fields().and_then(Verify::verify).err().unwrap();
    assert!(error.to_string().starts_with("details.header.account_id:"), "{error}");
    assert!(error.to_string().contains("account ID does not match witness"), "{error}");
}

#[test]
fn account_response_rejects_details_for_another_account_state() {
    let mut message = account_response();
    message.details.as_mut().unwrap().header.as_mut().unwrap().nonce += 1;

    let error = message.decode_fields().and_then(Verify::verify).err().unwrap();
    assert!(error.to_string().starts_with("details.header:"), "{error}");
    assert!(
        error.to_string().contains("account commitment does not match witness"),
        "{error}"
    );
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
    let decoded = encoded.decode_fields().and_then(Verify::verify).unwrap();

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

    let err = encoded.decode_fields().and_then(Verify::verify).unwrap_err();
    assert!(err.to_string().contains("result"));
}

#[test]
fn account_storage_map_details_rejects_false_limit_marker() {
    use crate::generated::rpc::account_storage_details::account_storage_map_details::Result;

    let encoded = crate::generated::rpc::account_storage_details::AccountStorageMapDetails {
        slot_name: test_slot_name().to_string(),
        result: Some(Result::TooManyEntries(false)),
    };

    let err = encoded.decode_fields().and_then(Verify::verify).unwrap_err();
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

    let err = encoded.decode_fields().and_then(Verify::verify).unwrap_err();
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

    let request = request.decode_fields().and_then(Verify::verify).unwrap();

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

    let err = request.decode_fields().and_then(Verify::verify).unwrap_err();

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

    let request = request.decode_fields().and_then(Verify::verify).unwrap();

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

    let err = request.decode_fields().and_then(Verify::verify).unwrap_err();

    assert!(err.to_string().contains("duplicate keys"));
}

#[test]
fn account_detail_request_allows_no_storage_slot_data() {
    let request = crate::generated::rpc::account_request::AccountDetailRequest {
        code_commitment: None,
        asset_vault_commitment: None,
        storage_request: None,
    };

    let request = request.decode_fields().and_then(Verify::verify).unwrap();

    assert_eq!(request.storage_request, AccountStorageRequest::None);
}
