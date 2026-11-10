use std::sync::Arc;

use anyhow::Context as _;
use miden_node_proto::DecodeMessageExt;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::miden::node::v1::BlockSubscriptionRequest;
use miden_node_store::state::{BlockWriter, State};
use miden_node_tracing::{Instrument, info, info_span, instrument, warn};
use miden_node_utils::retry::{self, RetryableWithContext};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::BlockNumber;
use tokio_stream::StreamExt;

use super::{RECONNECT_DELAY, RpcReadiness};

pub(super) struct BlockSync {
    pub(super) state: Arc<State>,
    pub(super) writer: BlockWriter,
    pub(super) source_rpc: RpcClient,
    pub(super) readiness: RpcReadiness,
}

impl BlockSync {
    pub(super) async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // `sync` needs `&mut self` (it applies blocks through the writer capability), so the retry
        // closure cannot lend out a borrow of a capture; thread `self` through as owned context
        // instead.
        let retry = (|mut sync: Self| {
            let shutdown = shutdown.clone();
            async move {
                let result = sync
                    .sync(shutdown)
                    .await
                    .and_then(|()| Err(anyhow::anyhow!("unexpected end of stream")));
                (sync, result)
            }
        })
        .retry(retry::constant(RECONNECT_DELAY, None))
        .context(self)
        .notify(|err, _| {
            warn!(err, "Block sync failed, retrying", retry.delay_ms = RECONNECT_DELAY);
        });

        tokio::select! {
            (_, result) = retry => result,
            () = shutdown.cancelled() => Ok(()),
        }
    }

    #[instrument(err)]
    pub(super) async fn sync(&mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let local_tip = self.state.committed_tip();
        let (parent, _) = self.state.view().get_block_header(Some(local_tip), false).await?;
        let mut parent = parent.context("local chain tip header not found")?;
        let mut client = self.source_rpc.clone();
        let upstream_tip = BlockNumber::from(
            client
                .status(tonic::Request::new(
                    miden_node_proto::generated::miden::node::v1::StatusRequest {},
                ))
                .await?
                .into_inner()
                .chain_tip,
        );
        self.readiness.update(upstream_tip, local_tip).await;

        let block_from = local_tip.child().as_u32();
        info!("Connecting to upstream RPC for blocks", block.from = block_from);

        let mut stream = client
            .block_subscription(BlockSubscriptionRequest { block_from })
            .await?
            .into_inner();

        loop {
            let result = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = stream.next() => result,
            };
            let Some(result) = result else {
                return Ok(());
            };
            let (block, upstream_tip, protocol_config) = result?
                .decode_and_verify_with(&parent)
                .context("failed to verify block from upstream")?;
            let next_parent = block.header().clone();
            // Each synced block gets its own root span: the surrounding `sync` span lives for the
            // whole subscription, so parenting under it would chain every block into one
            // never-exported trace.
            let block_span = info_span!(
                parent: None,
                "sync_block",
                block.number = block.header().block_num().as_u32(),
            );
            self.writer.apply_block(block, protocol_config).instrument(block_span).await?;
            parent = next_parent;

            let local_tip = self.state.committed_tip();
            self.readiness.update(upstream_tip, local_tip).await;
        }
    }
}
