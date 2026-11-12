//! Unary lookup of committed logs under a transaction's native account.

use miden_node_proto::DecodeMessageExt;
use miden_node_proto::domain::transaction_logs::GetTransactionLogsRequest;
use miden_node_proto::generated::miden::node::v1::{
    GetTransactionLogsRequest as ProtoRequest,
    GetTransactionLogsResponse as ProtoResponse,
};
use miden_node_proto::generated::server::miden_node_v1_node_service::GetTransactionLogs;
use miden_node_tracing::{error, instrument};
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;
use tonic::{Code, Result as TonicResult, Status};

use super::RpcService;
use super::error_codes::{GetTransactionLogsErrorCode, internal_error};

pub(super) const MAX_ACTIVE_REQUESTS: usize = 32;

#[tonic::async_trait]
impl GetTransactionLogs for RpcService {
    type Input = GetTransactionLogsRequest;
    type Output = ProtoResponse;

    fn decode(request: ProtoRequest) -> TonicResult<Self::Input> {
        request
            .decode_and_verify()
            .map_err(|err| GetTransactionLogsErrorCode::DeserializationFailed.invalid_argument(err))
    }

    fn encode(response: Self::Output) -> TonicResult<ProtoResponse> {
        Ok(response)
    }

    #[instrument(name = "get_transaction_logs", fields(account.id = request.native_account_id, transaction.id = request.transaction_id))]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> TonicResult<Self::Output> {
        let _permit = self
            .transaction_log_requests
            .try_acquire()
            .map_err(|_| Status::resource_exhausted("Too many active transaction log requests"))?;
        let result = self.state.view().get_transaction_logs(request).await.map_err(|err| {
            error!(err, "Failed to read transaction logs");
            internal_error("Failed to read transaction logs")
        })?;
        let response = result.ok_or_else(|| {
            Status::with_details(
                Code::NotFound,
                "Transaction not found for native account",
                vec![GetTransactionLogsErrorCode::TransactionNotFound as u8].into(),
            )
        })?;
        Ok(response.into())
    }
}

#[cfg(test)]
mod tests {
    use futures::poll;
    use miden_protocol::Word;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
    use miden_protocol::transaction::TransactionId;

    use super::*;
    use crate::tests::transaction_log_test_service;

    fn request() -> GetTransactionLogsRequest {
        GetTransactionLogsRequest {
            native_account_id: ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
            transaction_id: TransactionId::from_raw(Word::empty()),
        }
    }

    #[tokio::test]
    async fn admission_rejects_excess_requests_and_recovers_after_error_and_cancellation() {
        let service = transaction_log_test_service().await;
        let held = service
            .transaction_log_requests
            .acquire_many(MAX_ACTIVE_REQUESTS as u32)
            .await
            .unwrap();
        let error = service
            .handle(request(), &MetadataMap::new(), &Extensions::new())
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::ResourceExhausted);
        drop(held);
        let held = service
            .transaction_log_requests
            .acquire_many((MAX_ACTIVE_REQUESTS - 1) as u32)
            .await
            .unwrap();
        for _ in 0..2 {
            let error = service
                .handle(request(), &MetadataMap::new(), &Extensions::new())
                .await
                .unwrap_err();
            assert_eq!(error.code(), Code::NotFound);
        }
        let metadata = MetadataMap::new();
        let extensions = Extensions::new();
        let mut pending = Box::pin(service.handle(request(), &metadata, &extensions));
        assert!(poll!(&mut pending).is_pending());
        let error = service.handle(request(), &metadata, &extensions).await.unwrap_err();
        assert_eq!(error.code(), Code::ResourceExhausted);
        drop(pending);
        let error = service.handle(request(), &metadata, &extensions).await.unwrap_err();
        assert_eq!(error.code(), Code::NotFound);
        drop(held);
    }
}
