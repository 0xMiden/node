use std::collections::HashSet;

use miden_node_proto::domain::account::{
    AccountRequest,
    AccountResponse,
    AccountStorageRequest,
    SlotData,
};
use miden_node_proto::generated as proto;
use miden_node_store::GetAccountError;
use miden_node_utils::limiter::{QueryParamStorageMapKeyTotalLimit, QueryParamStorageMapSlotLimit};
use tonic::Status;
use tracing::{Span, debug, field, info_span, instrument};

use super::{RpcService, check};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetAccount for RpcService {
    type Input = AccountRequest;
    type Output = AccountResponse;

    fn decode(request: proto::rpc::AccountRequest) -> tonic::Result<Self::Input> {
        AccountRequest::try_from(request).map_err(Into::into)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::AccountResponse> {
        Ok(output.into())
    }

    #[instrument(
        target = COMPONENT,
        name = "get_account",
        skip_all,
        fields(
            account.id = %request.account_id,
            block.number = field::Empty,
        ),
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        if let Some(block) = request.block_num {
            Span::current().record("block.number", field::display(block));
        }
        tracing::trace!(target: LOG_TARGET, ?request);
        debug!(target: LOG_TARGET, "Getting account");

        // Validate storage map request limits before forwarding to store.
        if let Some(details) = &request.details {
            let _span = info_span!(target: COMPONENT, "validate_storage_map_keys").entered();
            validate_storage_request(&details.storage_request)?;
        }

        let account_data =
            self.store.get_account(request).await.map_err(get_account_error_to_status)?;
        Ok(account_data)
    }
}

// HELPERS
// ================================================================================================

/// Validates the storage map request limits before forwarding it to the store.
///
/// Only the [`AccountStorageRequest::Explicit`] variant carries a user-controlled list of
/// slots. [`AccountStorageRequest::AllStorageMaps`] is expanded by the store from the account's
/// actual storage layout (and bounded by a response budget), so it needs no validation here.
fn validate_storage_request(storage_request: &AccountStorageRequest) -> Result<(), Status> {
    let AccountStorageRequest::Explicit(requests) = storage_request else {
        return Ok(());
    };

    // Bound the number of requested slots. `all-entries` requests are not counted by the per-key
    // limit below, so without this an unbounded (or duplicated) list of `all-entries` slots could
    // force the store into arbitrarily many forest lookups and database reconstructions, a
    // denial-of-service vector.
    check::<QueryParamStorageMapSlotLimit>(requests.len())?;

    // Reject duplicate slots: requesting the same slot more than once is redundant and would
    // otherwise multiply the store-side work for that slot.
    let mut seen = HashSet::with_capacity(requests.len());
    for request in requests {
        if !seen.insert(&request.slot_name) {
            return Err(Status::invalid_argument(format!(
                "duplicate storage map slot in request: {}",
                request.slot_name
            )));
        }
    }

    let total_keys: usize = requests
        .iter()
        .filter_map(|request| match &request.slot_data {
            SlotData::All => None,
            SlotData::MapKeys(items) => Some(items.len()),
        })
        .sum();
    check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;

    Ok(())
}

fn get_account_error_to_status(err: GetAccountError) -> Status {
    let message = err.to_string();
    match err {
        GetAccountError::DatabaseError(err) => super::database_error_to_status(&err),
        GetAccountError::DeserializationFailed(_)
        | GetAccountError::AccountNotFound(..)
        | GetAccountError::AccountNotPublic(_)
        | GetAccountError::UnknownBlock(_)
        | GetAccountError::BlockPruned(_) => Status::invalid_argument(message),
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_node_proto::domain::account::StorageMapRequest;
    use miden_node_utils::limiter::QueryParamLimiter;
    use miden_protocol::account::{StorageMapKey, StorageSlotName};
    use tonic::Code;

    use super::*;

    fn slot_request(name: &str, slot_data: SlotData) -> StorageMapRequest {
        StorageMapRequest {
            slot_name: StorageSlotName::new(name).unwrap(),
            slot_data,
        }
    }

    #[test]
    fn none_and_all_storage_maps_requests_are_always_valid() {
        validate_storage_request(&AccountStorageRequest::None).unwrap();
        validate_storage_request(&AccountStorageRequest::AllStorageMaps).unwrap();
    }

    #[test]
    fn explicit_request_within_limits_is_valid() {
        let requests = vec![
            slot_request("a::0", SlotData::All),
            slot_request("a::1", SlotData::MapKeys(vec![StorageMapKey::from_index(1)])),
        ];

        validate_storage_request(&AccountStorageRequest::Explicit(requests)).unwrap();
    }

    #[test]
    fn too_many_all_entries_slots_are_rejected() {
        // `all-entries` requests are not counted by the per-key limit, so this must be caught by
        // the per-slot limit.
        let requests = (0..=QueryParamStorageMapSlotLimit::LIMIT)
            .map(|index| slot_request(&format!("a::{index}"), SlotData::All))
            .collect();

        let status = validate_storage_request(&AccountStorageRequest::Explicit(requests))
            .expect_err("request exceeding the slot limit must be rejected");
        assert_eq!(status.code(), Code::OutOfRange);
    }

    #[test]
    fn duplicate_slots_are_rejected() {
        let requests =
            vec![slot_request("a::0", SlotData::All), slot_request("a::0", SlotData::All)];

        let status = validate_storage_request(&AccountStorageRequest::Explicit(requests))
            .expect_err("duplicate slot must be rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[test]
    fn too_many_map_keys_are_rejected() {
        let keys: Vec<_> = (0..=QueryParamStorageMapKeyTotalLimit::LIMIT)
            .map(|index| StorageMapKey::from_index(index as u32))
            .collect();
        let requests = vec![slot_request("a::0", SlotData::MapKeys(keys))];

        let status = validate_storage_request(&AccountStorageRequest::Explicit(requests))
            .expect_err("request exceeding the key limit must be rejected");
        assert_eq!(status.code(), Code::OutOfRange);
    }
}
