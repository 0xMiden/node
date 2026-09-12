use std::collections::HashMap;
use std::error::Error;

use miden_node_proto::domain::account::AccountStorageRequest;
use miden_node_proto::errors::conversion_error_to_status;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::utils::serde::DeserializationError;
use prost::Message;

fn account_request() -> proto::rpc::AccountRequest {
    let account_id = AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    proto::rpc::AccountRequest {
        account_id: Some(account_id.into()),
        block_num: None,
        details: None,
    }
}

#[test]
fn account_request_preserves_optional_fields_on_the_wire() {
    let request = account_request();
    let decoded = proto::rpc::AccountRequest::decode(request.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap();
    assert!(decoded.block_num.is_none());
    assert!(decoded.details.is_none());

    let request = proto::rpc::AccountRequest {
        block_num: Some(miden_protocol::block::BlockNumber::GENESIS.into()),
        details: Some(proto::rpc::account_request::AccountDetailRequest {
            code_commitment: Some(Word::empty().into()),
            ..Default::default()
        }),
        ..account_request()
    };
    let decoded = proto::rpc::AccountRequest::decode(request.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(decoded.block_num.unwrap().as_u32(), 0);
    let details = decoded.details.unwrap();
    assert_eq!(details.code_commitment, Some(Word::empty()));
    assert!(details.asset_vault_commitment.is_none());
    assert_eq!(details.storage_request, AccountStorageRequest::None);
}

#[test]
fn missing_account_id_is_an_invalid_argument() {
    let error = proto::rpc::AccountRequest::default().decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("account_id:"), "{error}");
    let status = conversion_error_to_status(error);
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("missing"));
}

#[test]
fn nested_map_keys_report_the_field_index_and_original_error() {
    use detail::storage_map_detail_request::{MapKeys, SlotData};
    use proto::rpc::account_request::account_detail_request as detail;

    let request = proto::rpc::AccountRequest {
        details: Some(proto::rpc::account_request::AccountDetailRequest {
            storage_request: Some(detail::StorageRequest::StorageMaps(
                detail::StorageMapDetailRequests {
                    storage_maps: vec![detail::StorageMapDetailRequest {
                        slot_name: "miden::test::map".into(),
                        slot_data: Some(SlotData::MapKeys(MapKeys {
                            map_keys: vec![
                                Word::empty().into(),
                                proto::primitives::Word { encoded: vec![0xff; 32] },
                            ],
                        })),
                    }],
                },
            )),
            ..Default::default()
        }),
        ..account_request()
    };
    let error = request.decode_fields().unwrap_err();
    assert!(error.to_string().starts_with(
        "details.storage_request.storage_maps.storage_maps[0].slot_data.map_keys.map_keys[1].encoded:"
    ), "{error}");
    assert!(error.source().unwrap().is::<DeserializationError>());
}

#[test]
fn account_details_require_vault_data_but_allow_absent_code() {
    let account_id = account_request().decode_fields().unwrap().verify().unwrap().account_id;
    let header = miden_protocol::account::AccountHeader::new(
        account_id,
        miden_protocol::Felt::ONE,
        Word::empty(),
        Word::empty(),
        Word::empty(),
    );
    let storage = miden_protocol::account::AccountStorageHeader::new(Vec::new()).unwrap();
    let details = proto::rpc::account_response::AccountDetails {
        header: Some(header.into()),
        storage_details: Some(proto::rpc::AccountStorageDetails {
            header: Some(storage.into()),
            map_details: Vec::new(),
        }),
        code: None,
        vault_details: Some(proto::rpc::AccountVaultDetails::default()),
    };
    let decoded = details.clone().decode_fields().unwrap().verify().unwrap();
    assert!(decoded.account_code.is_none());

    let error = proto::rpc::account_response::AccountDetails { vault_details: None, ..details }
        .decode_fields()
        .unwrap_err();
    assert!(error.to_string().starts_with("vault_details:"), "{error}");
}

#[test]
fn absent_blocks_and_scripts_remain_optional() {
    let block = proto::rpc::MaybeBlock::default().decode_fields().unwrap();
    assert!(block.block.is_none());
    assert!(block.proof.is_none());
    assert!(proto::rpc::MaybeNoteScript::default().decode_fields().unwrap().script.is_none());
}

#[test]
fn prover_requires_a_request_variant() {
    let error = proto::remote_prover::ProofRequest::default().decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("request:"), "{error}");
}

#[test]
fn rpc_limits_preserve_endpoint_and_parameter_names() {
    let parameters = HashMap::from([("max_items".to_string(), 10), ("max_bytes".to_string(), 0)]);
    let message = proto::rpc::RpcLimits {
        endpoints: HashMap::from([(
            "SyncNotes".to_string(),
            proto::rpc::EndpointLimits { parameters: parameters.clone() },
        )]),
    };
    let decoded = proto::rpc::RpcLimits::decode(message.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap();
    assert_eq!(decoded, HashMap::from([("SyncNotes".to_string(), parameters)]));
}
