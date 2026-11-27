use std::collections::HashSet;

use miden_node_proto::domain::account::StorageMapEntries;
use miden_node_proto::{DecodeMessage, generated as proto};
use miden_node_store::GetAccountError;
use miden_node_tracing::{instrument, miden_span_record};
use miden_node_utils::limiter::{QueryParamStorageMapKeyTotalLimit, QueryParamStorageMapSlotLimit};
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;
use proto::miden::node::v2;
use tonic::Status;

use super::get_account::get_account_error_to_status;
use super::get_account_infos::{account_id, required_height};
use super::{RpcService, check};

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::GetAccountStorageWitnesses for RpcService {
    type Input = (AccountId, BlockNumber, Vec<(StorageSlotName, Vec<StorageMapKey>)>);
    type Output = v2::GetAccountStorageWitnessesResponse;

    fn decode(request: v2::GetAccountStorageWitnessesRequest) -> tonic::Result<Self::Input> {
        let target = required_height(request.block_num)?;
        let account = account_id(request.account_id)?;
        if !account.is_public() {
            return Err(Status::invalid_argument("public account required"));
        }
        check::<QueryParamStorageMapSlotLimit>(request.maps.len())?;
        check::<QueryParamStorageMapKeyTotalLimit>(
            request.maps.iter().map(|query| query.keys.len()).sum(),
        )?;
        let mut names = HashSet::new();
        let entries = request
            .maps
            .into_iter()
            .map(|query| {
                let slot_name = StorageSlotName::new(query.slot_name)
                    .map_err(|err| Status::invalid_argument(err.to_string()))?;
                if !names.insert(slot_name.clone()) {
                    return Err(Status::invalid_argument("duplicate storage map slot"));
                }
                let keys = query
                    .keys
                    .into_iter()
                    .map(|word| {
                        word.decode_fields()
                            .map(StorageMapKey::new)
                            .map_err(|err| Status::invalid_argument(err.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((slot_name, keys))
            })
            .collect::<Result<Vec<_>, Status>>()?;

        Ok((account, target, entries))
    }

    fn encode(output: Self::Output) -> tonic::Result<v2::GetAccountStorageWitnessesResponse> {
        Ok(output)
    }

    #[instrument(name = "get_account_storage_witnesses", err)]
    async fn handle(
        &self,
        (account, target, entries): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        if miden_node_tracing::enabled!(tracing::Level::INFO) {
            let keys = entries.iter().flat_map(|(_, keys)| keys);
            miden_span_record!(
                block.number = target,
                account.id = account,
                account.storage.slot.count = entries.len(),
                account.storage.slots =
                    super::trace_sample(&entries).iter().map(|(slot, _)| slot).collect::<Vec<_>>(),
                account.storage.map.keys = keys.take(super::TRACE_SAMPLE_SIZE).collect::<Vec<_>>(),
            );
        }

        let details = self
            .state
            .read(move |view| {
                let (block, storage) =
                    super::get_account_witnesses::witness_headers(&view, account, target)?;
                miden_node_store::read::validate_storage_map_slots(
                    account,
                    block,
                    entries.iter().map(|(slot, _)| slot),
                    &storage,
                )?;
                entries
                    .into_iter()
                    .map(|(slot, keys)| {
                        view.snapshot
                            .storage_map_witness(account, block, &slot, keys)
                            .map_err(GetAccountError::from)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .await
            .map_err(get_account_error_to_status)?;

        let maps = details
            .into_iter()
            .map(|slot| {
                let StorageMapEntries::PartialMap { partial_smt, .. } = slot.entries else {
                    return Err(super::error_codes::internal_error(
                        "missing requested storage map proof",
                    ));
                };
                Ok(v2::get_account_storage_witnesses_response::MapWitness {
                    slot_name: slot.slot_name.to_string(),
                    map: Some(partial_smt.into()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(v2::GetAccountStorageWitnessesResponse { block_num: target.as_u32(), maps })
    }
}
