use std::num::NonZeroUsize;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{AccountVaultCursor, AccountVaultValue, State};
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_node_utils::grpc::ClientIp;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use super::sync_stream::{Paginator, SyncStream};
use super::{RpcService, database_error_to_status, invalid_block_range_to_status};
use crate::{COMPONENT, LOG_TARGET};

/// Database rows fetched per page. This bounds internal work and memory, not encoded response size.
const DB_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(256).unwrap();
/// Stream items buffered before backpressure pauses the database producer.
const STREAM_BUFFER_SIZE: usize = 32;
/// Maximum time a stream producer waits for a stalled client to accept one update.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

type RequestInput = (AccountId, RangeInclusive<BlockNumber>);

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncAccountVaultV2 for RpcService {
    type Input = RequestInput;
    type Item = AccountVaultValue;
    type ItemStream = ReceiverStream<tonic::Result<Self::Item>>;

    fn decode(
        request: proto::miden::node::v1::SyncAccountVaultV2Request,
    ) -> tonic::Result<Self::Input> {
        let request = request
            .decode_fields()
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let account_id = request
            .account_id
            .verify()
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let block_range = request.block_range.verify().map_err(invalid_block_range_to_status)?;

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
            block_range.from = block_range.start(),
            block_range.to = block_range.end(),
        );

        tracing::debug!(target: LOG_TARGET, "Streaming account vault updates");

        if !account_id.is_public() {
            return Err(Status::invalid_argument(format!("account {account_id} is not public")));
        }

        let permit = self.sync_stream_limiter.acquire(ClientIp::from_extensions(extensions))?;
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
    block_range: RangeInclusive<BlockNumber>,
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
        let page = self
            .state
            .view()
            .sync_account_vault_v2_page(
                self.account_id,
                self.block_range.clone(),
                self.cursor.take(),
                DB_PAGE_SIZE,
            )
            .await
            .map_err(|err| database_error_to_status(&err))?;
        self.done = page.next_cursor.is_none();
        self.cursor = page.next_cursor;
        Ok((!page.values.is_empty()).then_some(page.values))
    }
}
