//! Catch-up from the configured full node's committed block stream.

use std::time::Duration;

use anyhow::{Context, ensure};
use miden_node_proto::DecodeMessageExt;
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated::miden::node::v1::{
    BlockSubscriptionRequest,
    BlockSubscriptionResponse,
};
use miden_node_tracing::{info, warn};
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::BlockHeader;
use tokio::sync::{OwnedMutexGuard, OwnedRwLockReadGuard, watch};
use tokio::time::timeout;
use tokio_stream::{Stream, StreamExt};
use tokio_util::task::TaskTracker;
use url::Url;

use super::ValidatorService;
use crate::db::ValidatorDbWriter;

pub(super) struct Recovery {
    client: RpcClient,
    timeout: Duration,
    pub(super) running: watch::Sender<bool>,
    stop: CancellationToken,
    tasks: TaskTracker,
}

impl ValidatorService {
    pub(crate) fn configure_recovery(
        &mut self,
        url: Url,
        grpc: GrpcOptions,
        stop: CancellationToken,
        tasks: TaskTracker,
    ) -> anyhow::Result<()> {
        ensure!(
            matches!(url.scheme(), "http" | "https") && url.host().is_some(),
            "invalid recovery RPC URL"
        );
        ensure!(!grpc.request_timeout.is_zero(), "recovery requires a positive gRPC timeout");
        let client = Builder::new(url)
            .max_decoding_message_size(grpc.message_size.max_decoding_message_size.get())
            .with_timeout(grpc.request_timeout)
            .with_tls()?
            .without_metadata_version()
            .with_metadata_genesis(self.genesis_commitment)
            .with_otel_context_injection()
            .connect_lazy();
        self.recovery = Some(Recovery {
            client,
            timeout: grpc.request_timeout,
            running: watch::channel(false).0,
            stop,
            tasks,
        });
        Ok(())
    }
}

impl Recovery {
    /// Transfers signing and backup exclusion to the worker before the triggering RPC returns.
    pub(super) fn start(
        &self,
        db: ValidatorDbWriter,
        parent: BlockHeader,
        signing: OwnedMutexGuard<()>,
        serving: OwnedRwLockReadGuard<()>,
    ) {
        let client = self.client.clone();
        let stop = self.stop.clone();
        let timeout = self.timeout;
        self.running.send_replace(true);
        let active = ActiveRecovery(self.running.clone());
        self.tasks.spawn(async move {
            let _ownership = (active, serving, signing);
            if let Err(error) = catch_up(client, db, parent, stop, timeout).await {
                warn!(error, "Validator catch-up interrupted");
            }
        });
    }
}

/// Wakes sign callers when the worker exits, including during unwinding.
struct ActiveRecovery(watch::Sender<bool>);

impl Drop for ActiveRecovery {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}

async fn catch_up(
    mut client: RpcClient,
    db: ValidatorDbWriter,
    parent: BlockHeader,
    stop: CancellationToken,
    wait: Duration,
) -> anyhow::Result<()> {
    let from = parent.block_num().child().as_u32();
    let request = BlockSubscriptionRequest { block_from: from };
    let stream = tokio::select! {
        biased;
        () = stop.cancelled() => return Ok(()),
        response = timeout(wait, client.block_subscription(request)) => {
            response.context("timed out opening the committed block stream")??.into_inner()
        }
    };
    apply_stream(stream, &db, parent, &stop, wait).await
}

/// Persists the verified prefix up to the tip advertised by the first response.
pub(super) async fn apply_stream(
    mut stream: impl Stream<Item = tonic::Result<BlockSubscriptionResponse>> + Unpin,
    db: &ValidatorDbWriter,
    mut parent: BlockHeader,
    stop: &CancellationToken,
    wait: Duration,
) -> anyhow::Result<()> {
    let mut target = None;
    loop {
        let event = tokio::select! {
            biased;
            () = stop.cancelled() => return Ok(()),
            event = timeout(wait, stream.next()) => {
                event.context("timed out waiting for a committed block")?
                    .context("committed stream ended before recovery target")??
            }
        };
        let (block, tip, config) = event.decode_and_verify_with(&parent)?;
        let height = block.header().block_num();
        let target = *target.get_or_insert(tip);
        ensure!(
            tip >= target && tip >= height,
            "inconsistent committed stream tip {tip} at {height}"
        );
        parent = block.header().clone();
        db.store_confirmed_block(block, config)
            .await
            .with_context(|| format!("storing confirmed block {height}"))?;
        if height == target {
            info!(
                "Validator catch-up complete",
                block.number = height,
                block.commitment = parent.commitment()
            );
            return Ok(());
        }
    }
}
