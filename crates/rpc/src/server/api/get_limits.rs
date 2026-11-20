use std::collections::HashMap;

use miden_node_proto::generated as proto;
use miden_node_proto::generated::miden::node::{v1, v2};
use miden_node_tracing::{debug, instrument};
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit as AccountId,
    QueryParamLimiter,
    QueryParamNoteIdLimit as NoteId,
    QueryParamNoteTagLimit as NoteTag,
    QueryParamNullifierPrefixLimit as NullifierPrefix,
    QueryParamStorageMapKeyTotalLimit as StorageMapKeyTotal,
    QueryParamStorageMapSlotLimit as StorageMapSlot,
    QueryParamVaultAssetLimit as VaultAsset,
};

use super::RpcService;

/// Parameter limits advertised by each version of this RPC service.
pub(super) struct RpcLimits {
    v1: v1::GetLimitsResponse,
    v2: v2::GetLimitsResponse,
}

fn limit<L: QueryParamLimiter>() -> (String, u32) {
    (L::PARAM_NAME.into(), L::LIMIT as u32)
}

impl RpcLimits {
    pub(super) fn new() -> Self {
        let shared = [
            ("GetNotesById", HashMap::from([limit::<NoteId>()])),
            ("SyncNotes", HashMap::from([limit::<NoteTag>()])),
            ("SyncNullifiers", HashMap::from([limit::<NullifierPrefix>()])),
            ("SyncTransactions", HashMap::from([limit::<AccountId>()])),
        ];
        let v1 = v1::GetLimitsResponse {
            endpoints: shared
                .iter()
                .cloned()
                .chain([(
                    "GetAccount",
                    HashMap::from([
                        limit::<StorageMapKeyTotal>(),
                        limit::<StorageMapSlot>(),
                        limit::<VaultAsset>(),
                    ]),
                )])
                .map(|(name, parameters)| (name.into(), v1::EndpointLimits { parameters }))
                .collect(),
        };
        let v2 = v2::GetLimitsResponse {
            endpoints: shared
                .into_iter()
                .map(|(name, parameters)| (name.into(), v2::EndpointLimits { parameters }))
                .collect(),
        };
        Self { v1, v2 }
    }
}

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::GetLimits for RpcService {
    type Input = ();
    type Output = v1::GetLimitsResponse;

    fn decode(_request: v1::GetLimitsRequest) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<v1::GetLimitsResponse> {
        Ok(output)
    }

    #[instrument(name = "get_limits")]
    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        debug!("Getting limits");

        Ok(self.limits.v1.clone())
    }
}

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::GetLimits for RpcService {
    type Input = ();
    type Output = v2::GetLimitsResponse;

    fn decode(_request: v2::GetLimitsRequest) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<v2::GetLimitsResponse> {
        Ok(output)
    }

    #[instrument(name = "get_limits_v2")]
    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        debug!("Getting limits");

        Ok(self.limits.v2.clone())
    }
}
