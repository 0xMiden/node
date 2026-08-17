use std::num::NonZeroUsize;
use std::ops::RangeInclusive;
use std::time::Duration;

use miden_node_proto::decode::{read_account_id, read_block_range};
use miden_node_proto::generated as proto;
use miden_node_store::{AccountVaultValue, AccountVaultValuesPage, StateView};
use miden_node_utils::tracing::{miden_instrument, miden_span_record};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::Instrument;

use super::{
    RpcInvalidBlockRange,
    RpcService,
    database_error_to_status,
    invalid_block_range_to_status,
};
use crate::{COMPONENT, LOG_TARGET};

/// Database rows fetched per page. This bounds internal work and memory, not encoded response size.
const DB_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(256).unwrap();
/// Stream items buffered before backpressure pauses the database producer.
const STREAM_BUFFER_SIZE: usize = 32;
/// Maximum time a stream producer waits for a stalled client to accept one update.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

type Input = (AccountId, RangeInclusive<BlockNumber>);

#[tonic::async_trait]
impl proto::server::rpc_api::SyncAccountVaultV2 for RpcService {
    type Input = Input;
    type Item = AccountVaultValue;
    type ItemStream = ReceiverStream<tonic::Result<Self::Item>>;

    fn decode(request: proto::rpc::SyncAccountVaultV2Request) -> tonic::Result<Self::Input> {
        let account_id =
            read_account_id::<proto::rpc::SyncAccountVaultV2Request, Status>(request.account_id)?;
        let range = read_block_range::<Status>(request.block_range, "SyncAccountVaultV2Request")?;
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;

        Ok((account_id, block_range))
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::AccountVaultUpdate> {
        let vault_key: Word = item.vault_key.into();
        Ok(proto::rpc::AccountVaultUpdate {
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
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        miden_span_record!(
            account.id = %account_id,
            block_range.from = %block_range.start(),
            block_range.to = %block_range.end(),
        );

        tracing::debug!(target: LOG_TARGET, "Streaming account vault updates");

        if !account_id.is_public() {
            return Err(Status::invalid_argument(format!("account {account_id} is not public")));
        }

        // Keep this view for the finite stream's lifetime. Besides fixing the chain-tip view used
        // for validation, this pins the history generation so pruning cannot remove rows between
        // internal database pages. Cancellation and the bounded send timeout release the view if
        // the client stops consuming the stream.
        let view = self.state.view();
        let first_page = view
            .sync_account_vault_v2_page(account_id, block_range.clone(), None, DB_PAGE_SIZE)
            .await
            .map_err(|err| database_error_to_status(&err))?;

        // Reserve a slot for a terminal error so a full data buffer cannot turn a timeout or
        // database failure into an apparently successful end-of-stream.
        let (tx, rx) = mpsc::channel(STREAM_BUFFER_SIZE + 1);
        let terminal_permit = tx
            .clone()
            .try_reserve_owned()
            .expect("a newly created vault sync channel must have capacity");
        VaultSyncProducer {
            view,
            account_id,
            block_range,
            page: first_page,
            tx,
            terminal_permit: Some(terminal_permit),
        }
        .spawn();

        Ok(ReceiverStream::new(rx))
    }
}

struct VaultSyncProducer {
    view: StateView,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
    page: AccountVaultValuesPage,
    tx: mpsc::Sender<tonic::Result<AccountVaultValue>>,
    terminal_permit: Option<mpsc::OwnedPermit<tonic::Result<AccountVaultValue>>>,
}

impl VaultSyncProducer {
    fn spawn(self) {
        tokio::spawn(self.run().instrument(tracing::Span::current()));
    }

    async fn run(mut self) {
        loop {
            let next_cursor = self.page.next_cursor.take();
            for value in std::mem::take(&mut self.page.values) {
                match self.tx.send_timeout(Ok(value), SEND_TIMEOUT).await {
                    Ok(()) => {},
                    Err(SendTimeoutError::Closed(_)) => return,
                    Err(SendTimeoutError::Timeout(_)) => {
                        self.send_terminal_error(Status::deadline_exceeded(
                            "account vault sync client stopped consuming updates",
                        ));
                        return;
                    },
                }
            }

            let Some(cursor) = next_cursor else {
                return;
            };

            self.page = match self
                .view
                .sync_account_vault_v2_page(
                    self.account_id,
                    self.block_range.clone(),
                    Some(cursor),
                    DB_PAGE_SIZE,
                )
                .await
            {
                Ok(page) => page,
                Err(err) => {
                    self.send_terminal_error(database_error_to_status(&err));
                    return;
                },
            };
        }
    }

    fn send_terminal_error(&mut self, status: Status) {
        self.terminal_permit
            .take()
            .expect("terminal permit is consumed at most once")
            .send(Err(status));
    }
}
