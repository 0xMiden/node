use miden_node_proto::domain::account::{
    AccountRequest,
    AccountResponse,
    AccountStorageRequest,
    SlotData,
};
use miden_node_proto::generated as proto;
use miden_node_store::GetAccountError;
use miden_node_utils::limiter::QueryParamStorageMapKeyTotalLimit;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use tonic::Status;
use tracing::{Span, debug, info_span};

use super::{COMPONENT, RpcService, check};

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

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: COMPONENT, ?request);

        let span = Span::current();
        span.set_attribute("account.id", request.account_id);
        if let Some(block) = request.block_num {
            span.set_attribute("block.number", block);
        }

        // Validate total storage map key limit before forwarding to store
        if let Some(details) = &request.details {
            let _span = info_span!(target: COMPONENT, "validate_storage_map_keys").entered();
            let total_keys: usize = match &details.storage_request {
                AccountStorageRequest::None | AccountStorageRequest::AllStorageMaps => 0,
                AccountStorageRequest::Explicit(requests) => requests
                    .iter()
                    .filter_map(|request| match &request.slot_data {
                        SlotData::All => None,
                        SlotData::MapKeys(items) => Some(items.len()),
                    })
                    .sum(),
            };
            check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;
        }

        let account_data =
            self.store.get_account(request).await.map_err(get_account_error_to_status)?;
        Ok(account_data)
    }
}

// HELPERS
// ================================================================================================

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
