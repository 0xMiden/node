use std::collections::HashSet;

use miden_node_proto::domain::account::{
    AccountStorageRequest,
    GetAccountRequest,
    GetAccountResponse,
};
use miden_node_proto::generated::miden::node::v1::get_account_request::AccountDetailRequest;
use miden_node_proto::generated::miden::node::v1::get_account_request::account_detail_request::{
    StorageRequest, VaultRequest, storage_map_detail_request::SlotData,
};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::{DecodeMessageExt, generated as proto};
use miden_node_store::DatabaseError;
use miden_node_tracing::{debug, info_span, instrument, miden_span_record};
use miden_node_utils::limiter::{
    QueryParamStorageMapKeyTotalLimit,
    QueryParamStorageMapSlotLimit,
    QueryParamVaultAssetLimit,
};
use miden_protocol::account::{AccountId, StorageSlotName};
use miden_protocol::block::BlockNumber;
use tonic::Status;

use super::error_codes::GetAccountErrorCode;
use super::{RpcService, check};

mod read;
#[cfg(test)]
pub(crate) use read::get_account as read_account;

// ERRORS
// ================================================================================================

/// Errors produced while reading an account witness and its details from the store.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GetAccountError {
    #[error("database error")]
    DatabaseError(#[from] DatabaseError),
    #[error("malformed request")]
    DeserializationFailed(#[from] ConversionError),
    #[error("account {0} not found at block {1}")]
    AccountNotFound(AccountId, BlockNumber),
    #[error("account {0} is not public")]
    AccountNotPublic(AccountId),
    #[error("block {0} is unknown")]
    UnknownBlock(BlockNumber),
    #[error("block {0} has been pruned")]
    BlockPruned(BlockNumber),
    #[error("account {account_id} has no storage slot {slot_name} at block {block_num}")]
    StorageSlotNotFound {
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
    },
    #[error(
        "storage slot {slot_name} of account {account_id} is not a map slot at block {block_num}"
    )]
    StorageSlotNotMap {
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
    },
}

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::GetAccount for RpcService {
    type Input = GetAccountRequest;
    type Output = GetAccountResponse;

    fn decode(request: proto::miden::node::v1::GetAccountRequest) -> tonic::Result<Self::Input> {
        if let Some(details) = &request.details {
            check_request_limits(details)?;
        }
        request
            .decode_and_verify()
            .map_err(|err| GetAccountErrorCode::DeserializationFailed.invalid_argument(err))
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::miden::node::v1::GetAccountResponse> {
        Ok(output.into())
    }

    #[instrument(name = "get_account")]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(account.id = request.account_id, block.number = request.block_num);
        debug!(
            "Getting account",
            account.id = request.account_id,
            block.number = request.block_num
        );

        if let Some(details) = &request.details {
            let _span = info_span!("validate_account_details").entered();
            check_duplicate_slots(&details.storage_request)?;
        }

        let account_data = self
            .state
            .read(move |view| read::get_account(&view, request))
            .await
            .map_err(get_account_error_to_status)?;
        Ok(account_data)
    }
}

// HELPERS
// ================================================================================================

/// Bounds the requested proofs before converting individual asset IDs, slots, and map keys.
fn check_request_limits(details: &AccountDetailRequest) -> Result<(), Status> {
    if let Some(VaultRequest::AssetIds(ids)) = &details.vault_request {
        check::<QueryParamVaultAssetLimit>(ids.asset_ids.len())?;
    }
    if let Some(StorageRequest::StorageMaps(maps)) = &details.storage_request {
        check::<QueryParamStorageMapSlotLimit>(maps.storage_maps.len())?;
        let total_keys = maps
            .storage_maps
            .iter()
            .map(|slot| match &slot.slot_data {
                Some(SlotData::MapKeys(keys)) => keys.map_keys.len(),
                _ => 0,
            })
            .sum();
        check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;
    }
    Ok(())
}

/// Rejects repeated slot names before querying the store.
fn check_duplicate_slots(storage_request: &AccountStorageRequest) -> Result<(), Status> {
    let AccountStorageRequest::Explicit(requests) = storage_request else {
        return Ok(());
    };
    let mut seen = HashSet::with_capacity(requests.len());
    for request in requests {
        if !seen.insert(&request.slot_name) {
            return Err(GetAccountErrorCode::DeserializationFailed.invalid_argument(format!(
                "duplicate storage map slot in request: {}",
                request.slot_name
            )));
        }
    }

    Ok(())
}

fn get_account_error_to_status(err: GetAccountError) -> Status {
    let message = err.to_string();
    match err {
        GetAccountError::DatabaseError(err) => super::database_error_to_status(&err),
        GetAccountError::DeserializationFailed(err) => {
            GetAccountErrorCode::DeserializationFailed.invalid_argument(err)
        },
        GetAccountError::AccountNotFound(..) => {
            GetAccountErrorCode::AccountNotFound.invalid_argument(message)
        },
        GetAccountError::AccountNotPublic(_) => {
            GetAccountErrorCode::AccountNotPublic.invalid_argument(message)
        },
        GetAccountError::UnknownBlock(_) => {
            GetAccountErrorCode::UnknownBlock.invalid_argument(message)
        },
        GetAccountError::BlockPruned(_) => {
            GetAccountErrorCode::BlockPruned.invalid_argument(message)
        },
        GetAccountError::StorageSlotNotFound { .. } => {
            GetAccountErrorCode::StorageSlotNotFound.invalid_argument(message)
        },
        GetAccountError::StorageSlotNotMap { .. } => {
            GetAccountErrorCode::StorageSlotNotMap.invalid_argument(message)
        },
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use proto::asset::AssetId;
    use proto::primitives::Word;
    use miden_node_proto::domain::account::{StorageMapRequest, SlotData as DomainSlotData};
    use miden_node_proto::generated::miden::node::v1::get_account_request::account_detail_request::{
        StorageMapDetailRequest, StorageMapDetailRequests, VaultAssetIds, storage_map_detail_request::MapKeys,
    };
    use proto::server::miden_node_v1_node_service::GetAccount as _;
    use miden_node_utils::limiter::QueryParamLimiter;
    use miden_protocol::account::{AccountId, StorageSlotName};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
    use tonic::Code;

    use super::*;

    #[test]
    fn pruned_block_error_includes_error_code() {
        let status = get_account_error_to_status(GetAccountError::BlockPruned(1.into()));
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.details(), &[5]);
    }

    #[test]
    fn invalid_storage_slot_errors_include_error_codes() {
        let account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let slot_name = StorageSlotName::new("a::0").unwrap();

        let status = get_account_error_to_status(GetAccountError::StorageSlotNotFound {
            account_id,
            slot_name: slot_name.clone(),
            block_num: 1.into(),
        });
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.details(), &[6]);

        let status = get_account_error_to_status(GetAccountError::StorageSlotNotMap {
            account_id,
            slot_name,
            block_num: 1.into(),
        });
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.details(), &[7]);
    }

    fn storage_details(storage_maps: Vec<StorageMapDetailRequest>) -> AccountDetailRequest {
        AccountDetailRequest {
            storage_request: Some(StorageRequest::StorageMaps(StorageMapDetailRequests {
                storage_maps,
            })),
            ..Default::default()
        }
    }

    #[test]
    fn request_limits_allow_full_and_explicit_selections() {
        for storage_request in [None, Some(StorageRequest::AllStorageMaps(true))] {
            check_request_limits(&AccountDetailRequest { storage_request, ..Default::default() })
                .unwrap();
        }

        let mut slots =
            vec![StorageMapDetailRequest::default(); QueryParamStorageMapSlotLimit::LIMIT];
        slots[0].slot_data = Some(SlotData::MapKeys(MapKeys {
            map_keys: vec![Word::default(); QueryParamStorageMapKeyTotalLimit::LIMIT],
        }));
        let mut details = storage_details(slots);
        details.vault_request = Some(VaultRequest::AssetIds(VaultAssetIds {
            asset_ids: vec![AssetId::default(); QueryParamVaultAssetLimit::LIMIT],
        }));
        check_request_limits(&details).unwrap();
    }

    #[test]
    fn excessive_proof_counts_take_precedence_over_malformed_fields() {
        let keys = |n| StorageMapDetailRequest {
            slot_data: Some(SlotData::MapKeys(MapKeys { map_keys: vec![Word::default(); n] })),
            ..Default::default()
        };
        for details in [
            storage_details(vec![
                StorageMapDetailRequest::default();
                QueryParamStorageMapSlotLimit::LIMIT + 1
            ]),
            storage_details(vec![keys(QueryParamStorageMapKeyTotalLimit::LIMIT), keys(1)]),
            AccountDetailRequest {
                vault_request: Some(VaultRequest::AssetIds(VaultAssetIds {
                    asset_ids: vec![AssetId::default(); QueryParamVaultAssetLimit::LIMIT + 1],
                })),
                ..Default::default()
            },
        ] {
            let request = proto::miden::node::v1::GetAccountRequest {
                details: Some(details),
                ..Default::default()
            };
            assert_eq!(RpcService::decode(request).unwrap_err().code(), Code::OutOfRange);
        }
    }

    #[test]
    fn duplicate_slots_are_rejected() {
        let slot = StorageMapRequest {
            slot_name: StorageSlotName::new("a::0").unwrap(),
            slot_data: DomainSlotData::All,
        };
        let status =
            check_duplicate_slots(&AccountStorageRequest::Explicit(vec![slot.clone(), slot]))
                .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.details(), &[1]);
    }
}
