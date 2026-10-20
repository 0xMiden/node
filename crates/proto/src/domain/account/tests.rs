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
    let request = proto::miden::node::v1::RegisterAccountRequest {
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

#[test]
fn invitation_check_request_debug_hides_invitation_code() {
    let code = "private invitation code";
    let request =
        proto::miden::node::v1::IsInvitationCodeValidRequest { invitation_code: code.to_owned() };
    assert!(!format!("{request:?}").contains(code));

    let decoded = request.decode_fields().unwrap();
    assert!(!format!("{decoded:?}").contains(code));
    assert_eq!(decoded.verify().unwrap(), code);
}

fn word_from_u32(arr: [u32; 4]) -> Word {
    Word::from(arr)
}

fn test_slot_name() -> StorageSlotName {
    StorageSlotName::new("miden::test::storage::slot").unwrap()
}

fn account_response() -> proto::miden::node::v1::GetAccountResponse {
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
    GetAccountResponse {
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

    let message = proto::miden::node::v1::GetAccountResponse { details: None, ..response };
    assert!(message.decode_fields().and_then(Verify::verify).unwrap().details.is_none());
}

fn account_request(block_num: Option<BlockNumber>) -> GetAccountRequest {
    GetAccountRequest {
        account_id: AccountId::dummy(
            [7; 15],
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        ),
        block_num,
        details: None,
    }
}

#[test]
fn account_response_verifies_requested_account_and_optional_block() {
    for (requested_block, returned_block) in [(Some(1), 1), (None, 1), (None, 17)] {
        for include_details in [true, false] {
            let mut message = account_response();
            message.block_num = Some(BlockNumber::from(returned_block).into());
            if !include_details {
                message.details = None;
            }
            let request = account_request(requested_block.map(BlockNumber::from));
            let response = message.decode_fields().unwrap().verify_with(&request).unwrap();
            assert_eq!(response.witness.id(), request.account_id);
            assert_eq!(response.block_num, BlockNumber::from(returned_block));
        }
    }
}

#[test]
fn account_response_rejects_an_unrequested_account() {
    let mut request = account_request(None);
    request.account_id = AccountId::dummy(
        [8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    for include_details in [true, false] {
        let mut message = account_response();
        if !include_details {
            message.details = None;
        }
        let error = message.decode_fields().unwrap().verify_with(&request).err().unwrap();
        assert!(error.to_string().contains("account ID does not match request"), "{error}");
    }
}

#[test]
fn account_response_rejects_an_unrequested_block() {
    let request = account_request(Some(2.into()));
    let error = account_response().decode_fields().unwrap().verify_with(&request).err().unwrap();
    assert!(error.to_string().contains("block number does not match request"), "{error}");
}

#[test]
fn account_response_request_verification_rejects_inconsistent_details() {
    let mut message = account_response();
    message.details.as_mut().unwrap().header.as_mut().unwrap().nonce += 1;
    let error = message
        .decode_fields()
        .unwrap()
        .verify_with(&account_request(Some(1.into())))
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("account commitment does not match witness"),
        "{error}"
    );
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
    let encoded: crate::generated::miden::node::v1::account_storage_details::AccountStorageMapDetails =
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
    let encoded =
        crate::generated::miden::node::v1::account_storage_details::AccountStorageMapDetails {
            slot_name: test_slot_name().to_string(),
            result: None,
        };

    let err = encoded.decode_fields().and_then(Verify::verify).unwrap_err();
    assert!(err.to_string().contains("result"));
}

#[test]
fn account_storage_map_details_rejects_false_limit_marker() {
    use crate::generated::miden::node::v1::account_storage_details::account_storage_map_details::Result;

    let encoded =
        crate::generated::miden::node::v1::account_storage_details::AccountStorageMapDetails {
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
    let encoded: crate::generated::miden::node::v1::AccountStorageDetails =
        AccountStorageDetails { header, map_details: vec![map_details] }.into();

    let err = encoded.decode_fields().and_then(Verify::verify).unwrap_err();
    assert!(err.to_string().contains("does not match storage header"));
}

#[test]
fn account_detail_request_converts_all_storage_maps() {
    use crate::generated::miden::node::v1::get_account_request::account_detail_request::StorageRequest;

    let request = crate::generated::miden::node::v1::get_account_request::AccountDetailRequest {
        code_commitment: None,
        vault_request: None,
        storage_request: Some(StorageRequest::AllStorageMaps(true)),
    };

    let request = request.decode_fields().and_then(Verify::verify).unwrap();

    assert_eq!(request.storage_request, AccountStorageRequest::AllStorageMaps);
}

#[test]
fn account_detail_request_rejects_false_all_storage_maps() {
    use crate::generated::miden::node::v1::get_account_request::account_detail_request::StorageRequest;

    let request = crate::generated::miden::node::v1::get_account_request::AccountDetailRequest {
        code_commitment: None,
        vault_request: None,
        storage_request: Some(StorageRequest::AllStorageMaps(false)),
    };

    let err = request.decode_fields().and_then(Verify::verify).unwrap_err();

    assert!(err.to_string().contains("all_storage_maps"));
}

#[test]
fn account_detail_request_converts_explicit_storage_maps() {
    use crate::generated::miden::node::v1::get_account_request::account_detail_request::{
        StorageMapDetailRequest,
        StorageMapDetailRequests,
        StorageRequest,
        storage_map_detail_request,
    };

    let request = crate::generated::miden::node::v1::get_account_request::AccountDetailRequest {
        code_commitment: None,
        vault_request: None,
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
    use crate::generated::miden::node::v1::get_account_request::account_detail_request::{
        StorageMapDetailRequest,
        StorageMapDetailRequests,
        StorageRequest,
        storage_map_detail_request,
    };
    use crate::generated::miden::node::v1::get_account_request::account_detail_request::storage_map_detail_request::MapKeys;

    let map_key: crate::generated::primitives::Word = Word::from([1, 2, 3, 4u32]).into();
    let request = crate::generated::miden::node::v1::get_account_request::AccountDetailRequest {
        code_commitment: None,
        vault_request: None,
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
    let request = crate::generated::miden::node::v1::get_account_request::AccountDetailRequest {
        code_commitment: None,
        vault_request: None,
        storage_request: None,
    };

    let request = request.decode_fields().and_then(Verify::verify).unwrap();

    assert_eq!(request.storage_request, AccountStorageRequest::None);
}

fn vault_fixture() -> (miden_protocol::asset::AssetVault, Vec<AssetId>) {
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    };
    let asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
            .unwrap()
            .into();
    let absent = AssetId::new_fungible(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap());
    (
        miden_protocol::asset::AssetVault::new(&[asset]).unwrap(),
        vec![asset.id(), absent],
    )
}

fn partial_vault_message() -> proto::miden::node::v1::AccountVaultDetails {
    let (vault, asset_ids) = vault_fixture();
    let partial = PartialVault::with_witnesses(asset_ids.iter().map(|id| vault.open(*id))).unwrap();
    AccountVaultDetails::Partial { asset_ids, vault: partial }.into()
}

fn account_response_with_vault(
    asset_ids: &[AssetId],
) -> proto::miden::node::v1::GetAccountResponse {
    let (vault, _) = vault_fixture();
    let partial = if asset_ids.is_empty() {
        PartialVault::new(vault.root())
    } else {
        PartialVault::with_witnesses(asset_ids.iter().map(|id| vault.open(*id))).unwrap()
    };
    let mut response = account_response().decode_fields().and_then(Verify::verify).unwrap();
    let details = response.details.as_mut().unwrap();
    let header = &details.account_header;
    details.account_header = AccountHeader::new(
        header.id(),
        header.nonce(),
        vault.root(),
        header.storage_commitment(),
        header.code_commitment(),
    );
    details.vault_details = AccountVaultDetails::Partial {
        asset_ids: asset_ids.to_vec(),
        vault: partial,
    };
    response.witness = AccountTree::with_entries([(
        details.account_header.id(),
        details.account_header.to_commitment(),
    )])
    .unwrap()
    .open(details.account_header.id());
    response.into()
}

fn vault_request(asset_ids: Vec<AssetId>) -> GetAccountRequest {
    GetAccountRequest {
        details: Some(AccountDetailRequest {
            code_commitment: None,
            vault_request: AccountVaultRequest::Assets(asset_ids),
            storage_request: AccountStorageRequest::None,
        }),
        ..account_request(Some(1.into()))
    }
}

#[test]
fn account_response_verifies_requested_vault_proofs_in_any_order() {
    let (expected, ids) = vault_fixture();
    for mut requested in [ids.clone(), vec![]] {
        let message = account_response_with_vault(&requested);
        requested.reverse();
        let response = message
            .decode_fields()
            .unwrap()
            .verify_with(&vault_request(requested.clone()))
            .unwrap();
        let AccountVaultDetails::Partial { vault, .. } = response.details.unwrap().vault_details
        else {
            panic!("expected partial vault")
        };
        for id in requested {
            assert_eq!(vault.open(id).unwrap(), expected.open(id));
        }
    }
}

#[test]
fn account_response_rejects_missing_requested_details_and_partial_vault() {
    let request = vault_request(vault_fixture().1);
    let message = account_response_with_vault(&vault_fixture().1);
    for vault_details in [
        None,
        Some(AccountVaultDetails::empty()),
        Some(AccountVaultDetails::LimitExceeded),
    ] {
        let mut message = message.clone();
        if let Some(vault_details) = vault_details {
            message.details.as_mut().unwrap().vault_details = Some(vault_details.into());
        } else {
            message.details = None;
        }
        assert!(message.decode_fields().unwrap().verify_with(&request).is_err());
    }
}

#[test]
fn account_response_rejects_missing_or_extra_vault_assets() {
    let ids = vault_fixture().1;
    for (requested, returned) in
        [(ids.clone(), vec![]), (ids.clone(), vec![ids[0]]), (vec![ids[0]], ids)]
    {
        let error = account_response_with_vault(&returned)
            .decode_fields()
            .unwrap()
            .verify_with(&vault_request(requested))
            .err()
            .unwrap();
        assert!(error.to_string().contains("does not cover the requested assets"), "{error}");
    }
}

#[test]
fn partial_vault_roundtrip_preserves_inclusion_and_absence_proofs() {
    let (expected, ids) = vault_fixture();
    let decoded = partial_vault_message().decode_fields().and_then(Verify::verify).unwrap();
    let AccountVaultDetails::Partial { asset_ids, vault } = decoded else {
        panic!("expected partial vault")
    };
    assert_eq!(asset_ids, ids);
    for id in ids {
        assert_eq!(vault.open(id).unwrap(), expected.open(id));
    }
}

#[test]
fn partial_vault_rejects_ambiguous_or_invalid_responses() {
    let valid = partial_vault_message();
    let mut invalid = valid.clone();
    invalid.too_many_assets = true;
    assert!(invalid.decode_fields().and_then(Verify::verify).is_err());

    let mut invalid = valid.clone();
    invalid.assets = vault_fixture().0.assets().map(Into::into).collect();
    assert!(invalid.decode_fields().and_then(Verify::verify).is_err());

    let mut invalid = valid.clone();
    let partial = invalid.partial_vault.as_mut().unwrap();
    partial.asset_ids.push(partial.asset_ids[0]);
    assert!(invalid.decode_fields().and_then(Verify::verify).is_err());

    let mut invalid = valid.clone();
    invalid.partial_vault.as_mut().unwrap().partial_smt =
        Some(PartialSmt::new(Word::empty()).into());
    assert!(invalid.decode_fields().and_then(Verify::verify).is_err());

    let mut invalid = valid;
    let partial = invalid.partial_vault.as_mut().unwrap();
    partial.asset_ids = vec![partial.asset_ids[0]; AccountVaultDetails::MAX_PROOF_ENTRIES + 1];
    assert!(invalid.decode_fields().and_then(Verify::verify).is_err());
}

#[test]
fn account_details_reject_partial_vault_with_wrong_root() {
    let mut response = account_response();
    response.details.as_mut().unwrap().vault_details = Some(partial_vault_message());
    let err = response.decode_fields().and_then(Verify::verify).err().unwrap();
    assert!(err.to_string().contains("partial vault root"));
}

#[test]
fn selective_vault_request_rejects_duplicate_ids() {
    use proto::miden::node::v1::get_account_request::account_detail_request::{
        VaultAssetIds,
        VaultRequest,
    };
    let ids = vault_fixture().1;
    for asset_ids in [ids.clone(), vec![], vec![ids[0], ids[0]]] {
        let request = proto::miden::node::v1::get_account_request::AccountDetailRequest {
            vault_request: Some(VaultRequest::AssetIds(VaultAssetIds {
                asset_ids: asset_ids.iter().copied().map(Into::into).collect(),
            })),
            ..Default::default()
        };
        let result = request.decode_fields().and_then(Verify::verify);
        if asset_ids == vec![ids[0], ids[0]] {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().vault_request, AccountVaultRequest::Assets(asset_ids));
        }
    }
}
