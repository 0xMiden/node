use miden_node_proto::errors::conversion_error_to_status;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{AccountLogCursor, MAX_ACCOUNT_LOG_PAGE_SIZE};
use miden_protocol::transaction::LogTopic;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use tonic::Status;

use super::{
    RpcInvalidBlockRange,
    RpcService,
    database_error_to_status,
    invalid_block_range_to_status,
};

#[tonic::async_trait]
impl proto::server::rpc_api::GetAccountLogs for RpcService {
    type Input = proto::rpc::DecodedGetAccountLogsRequest;
    type Output = proto::rpc::GetAccountLogsResponse;

    fn decode(request: proto::rpc::GetAccountLogsRequest) -> tonic::Result<Self::Input> {
        request.decode_fields().map_err(conversion_error_to_status)
    }
    fn encode(output: Self::Output) -> tonic::Result<Self::Output> {
        Ok(output)
    }

    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let account = request
            .account_id
            .verify()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let range = request
            .block_range
            .verify()
            .map_err(RpcInvalidBlockRange::from)
            .map_err(invalid_block_range_to_status)?;
        let topic = request
            .topic
            .map(|bytes| {
                if bytes.len() != LogTopic::SERIALIZED_SIZE {
                    return Err(Status::invalid_argument("topic must contain exactly 16 bytes"));
                }
                LogTopic::read_from_bytes(&bytes)
                    .map_err(|error| Status::invalid_argument(error.to_string()))
            })
            .transpose()?;
        let limit = if request.page_size == 0 { 128 } else { request.page_size };
        if limit > MAX_ACCOUNT_LOG_PAGE_SIZE {
            return Err(Status::invalid_argument("page_size exceeds 256"));
        }
        let after = request.after.map(|cursor| AccountLogCursor {
            block_num: cursor.block_num.into(),
            transaction_index: cursor.transaction_index,
            log_index: cursor.log_index,
        });
        if after.is_some_and(|cursor| {
            !range.contains(&cursor.block_num)
                || cursor.transaction_index as usize
                    >= miden_protocol::MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK
                || cursor.log_index as usize >= miden_protocol::MAX_LOGS_PER_TX
        }) {
            return Err(Status::invalid_argument(
                "cursor is outside the requested range or log limits",
            ));
        }
        let (tip, page) = self
            .state
            .with_view(async |view| {
                let page = view
                    .account_logs(account, range, topic, after, limit)
                    .await
                    .map_err(|error| database_error_to_status(&error))?;
                Ok::<_, Status>((view.tip(), page))
            })
            .await?;
        Ok(proto::rpc::GetAccountLogsResponse {
            chain_tip: tip.as_u32(),
            records: page
                .records
                .into_iter()
                .map(|record| proto::rpc::AccountLogRecord {
                    cursor: Some(cursor_to_proto(record.cursor)),
                    transaction_id: Some(record.transaction_id.into()),
                    native_account_id: Some(record.native_account_id.into()),
                    log: record.log.to_bytes(),
                })
                .collect(),
            next_cursor: page.next_cursor.map(cursor_to_proto),
        })
    }
}

fn cursor_to_proto(cursor: AccountLogCursor) -> proto::rpc::AccountLogCursor {
    proto::rpc::AccountLogCursor {
        block_num: cursor.block_num.as_u32(),
        transaction_index: cursor.transaction_index,
        log_index: cursor.log_index,
    }
}
