use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{AccountVaultCursor, AccountVaultValue, DatabaseError, State};
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_node_utils::grpc::ClientIp;
use miden_protocol::Word;
use miden_protocol::account::AccountId;

use super::error_codes::SyncAccountVaultV2ErrorCode as ErrorCode;
use super::sync_stream::{Paginator, SyncResponseStream, SyncStream};
use super::{RpcService, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

/// Database rows fetched per page. This bounds internal work and memory, not encoded response size.
const DB_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(256).unwrap();
/// Stream items buffered before backpressure pauses the database producer.
const STREAM_BUFFER_SIZE: usize = 32;
/// Maximum time a stream producer waits for a stalled client to accept one update.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

type RequestInput = (AccountId, SyncRange);

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncAccountVaultV2 for RpcService {
    type Input = RequestInput;
    type Item = AccountVaultValue;
    type ItemStream = SyncResponseStream<Self::Item>;

    fn decode(
        request: proto::miden::node::v1::SyncAccountVaultV2Request,
    ) -> tonic::Result<Self::Input> {
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let account_id = request
            .account_id
            .verify()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let block_range = match (
            request.block_range.map(std::convert::identity),
            request.range.map(std::convert::identity),
        ) {
            (Some(range), None) => range
                .verify()
                .map_err(|err| ErrorCode::InvalidRange.status(err.to_string()))?
                .into(),
            (None, Some(range)) => {
                range.verify().map_err(|err| ErrorCode::InvalidRange.status(err.to_string()))?
            },
            _ => {
                return Err(
                    ErrorCode::InvalidRange.status("exactly one synchronization range is required")
                );
            },
        };

        Ok((account_id, block_range))
    }

    fn encode(
        item: Self::Item,
    ) -> tonic::Result<proto::miden::node::v1::SyncAccountVaultV2Response> {
        let vault_key: Word = item.vault_key.into();
        Ok(proto::miden::node::v1::SyncAccountVaultV2Response {
            vault_key: Some(vault_key.into()),
            asset: item.asset.map(Into::into),
            block_num: item.block_num.as_u32(),
        })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "sync_account_vault_v2",
        err,
    )]
    async fn handle(
        &self,
        (account_id, block_range): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        miden_span_record!(
            account.id = account_id,
            block_range.from = block_range.from_exclusive.map(|block| block.as_u32()),
            block_range.to = block_range.target,
        );

        tracing::debug!(target: LOG_TARGET, "Streaming account vault updates");

        if !account_id.is_public() {
            return Err(
                ErrorCode::AccountNotPublic.status(format!("account {account_id} is not public"))
            );
        }

        let permit = self
            .sync_stream_limiter
            .acquire(ClientIp::from_extensions(extensions))
            .map_err(|err| ErrorCode::ResourceExhausted.status(err.message()))?;
        SyncStream::start(
            VaultPaginator {
                state: Arc::clone(&self.state),
                account_id,
                block_range,
                cursor: None,
                done: false,
            },
            permit,
            STREAM_BUFFER_SIZE,
            SEND_TIMEOUT,
        )
        .await
    }
}

struct VaultPaginator {
    state: Arc<State>,
    account_id: AccountId,
    block_range: SyncRange,
    cursor: Option<AccountVaultCursor>,
    done: bool,
}

#[tonic::async_trait]
impl Paginator for VaultPaginator {
    type Item = AccountVaultValue;

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
            .sync_account_vault_v2_page(
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
