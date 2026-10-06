use std::num::NonZeroUsize;
use std::sync::Arc;

use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{DatabaseError, State, StorageMapCursor, StorageMapValue};
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_protocol::account::AccountId;

use super::error_codes::SyncAccountStorageMapsV2ErrorCode as ErrorCode;
use super::stream_settings::{DB_PAGE_SIZE, SEND_TIMEOUT, STREAM_BUFFER_SIZE};
use super::sync_stream::{Paginator, SyncResponseStream, SyncStream};
use super::{RpcService, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

type RequestInput = (AccountId, SyncRange);

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncAccountStorageMapsV2 for RpcService {
    type Input = RequestInput;
    type Item = StorageMapValue;
    type ItemStream = SyncResponseStream<Self::Item>;

    fn decode(
        request: proto::miden::node::v1::SyncAccountStorageMapsV2Request,
    ) -> tonic::Result<Self::Input> {
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let account_id = request
            .account_id
            .verify()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let block_range = request
            .range
            .verify()
            .map_err(|err| ErrorCode::InvalidRange.status(err.to_string()))?;

        Ok((account_id, block_range))
    }

    fn encode(
        item: Self::Item,
    ) -> tonic::Result<proto::miden::node::v1::SyncAccountStorageMapsV2Response> {
        Ok(proto::miden::node::v1::SyncAccountStorageMapsV2Response {
            slot_name: item.slot_name.to_string(),
            key: Some(item.key.as_word().into()),
            value: Some(item.value.into()),
            last_updated_at: item.block_num.as_u32(),
        })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "sync_account_storage_maps_v2",
        err,
    )]
    async fn handle(
        &self,
        (account_id, block_range): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        miden_span_record!(
            account.id = account_id,
            block_range.from = block_range.from_exclusive.map(|block| block.as_u32()),
            block_range.to = block_range.target,
        );

        tracing::debug!(target: LOG_TARGET, "Streaming account storage-map updates");

        if !account_id.is_public() {
            return Err(
                ErrorCode::AccountNotPublic.status(format!("account {account_id} is not public"))
            );
        }

        SyncStream::start(
            StorageMapPaginator {
                state: Arc::clone(&self.state),
                account_id,
                block_range,
                cursor: None,
                done: false,
            },
            STREAM_BUFFER_SIZE,
            SEND_TIMEOUT,
        )
        .await
    }
}

struct StorageMapPaginator {
    state: Arc<State>,
    account_id: AccountId,
    block_range: SyncRange,
    cursor: Option<StorageMapCursor>,
    done: bool,
}

#[tonic::async_trait]
impl Paginator for StorageMapPaginator {
    type Item = StorageMapValue;

    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.done {
            return Ok(None);
        }
        // Even an empty delta must validate its target and retention horizon. Query one bounded
        // target row to reuse the same snapshot validation, then discard it.
        let range = self.block_range.database_range();
        let page = self
            .state
            .view()
            .sync_account_storage_maps_v2_page(
                self.account_id,
                range.clone().unwrap_or(self.block_range.target..=self.block_range.target),
                self.cursor.take(),
                if range.is_some() {
                    DB_PAGE_SIZE
                } else {
                    NonZeroUsize::MIN
                },
            )
            .await
            .map_err(|err| match err {
                DatabaseError::RangeBeyondTip(_) => ErrorCode::FutureTarget.status(err.to_string()),
                DatabaseError::BlockPruned { .. } => {
                    ErrorCode::HistoryUnavailable.status(err.to_string())
                },
                _ => database_error_to_status(&err),
            })?;
        if range.is_none() {
            self.done = true;
            return Ok(None);
        }
        self.done = page.next_cursor.is_none();
        self.cursor = page.next_cursor;
        Ok((!page.values.is_empty()).then_some(page.values))
    }
}

#[cfg(test)]
mod tests {
    use miden_node_proto::generated as proto;
    use miden_node_proto::prost::Message;
    use miden_node_store::StorageMapValue;
    use miden_protocol::account::{StorageMapKey, StorageSlotName};
    use miden_protocol::block::BlockNumber;
    use miden_protocol::{Felt, Word};
    use proto::server::miden_node_v1_node_service::SyncAccountStorageMapsV2;

    #[test]
    fn maximum_storage_update_fits_transport_limit() {
        let slot_name = StorageSlotName::new(format!("a::{}", "b".repeat(252))).unwrap();
        assert!(StorageSlotName::new(format!("a::{}", "b".repeat(253))).is_err());
        let word = Word::from([Felt::MAX; 4]);
        let item = super::RpcService::encode(StorageMapValue {
            block_num: BlockNumber::from(u32::MAX),
            slot_name,
            key: StorageMapKey::new(word),
            value: word,
        })
        .unwrap();
        assert!(item.encoded_len() < 4 * 1024 * 1024);
    }
}
