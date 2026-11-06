use std::sync::Arc;

use anyhow::Context as _;
use miden_node_proto::DecodeMessage;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::miden::node::v1::ProofSubscriptionRequest;
use miden_node_store::state::{ProofWriter, State};
use miden_node_tracing::{info_v2, warn_v2};
use miden_node_utils::retry::{self, RetryableWithContext};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::BlockNumber;
use tokio_stream::StreamExt;

use super::RECONNECT_DELAY;

pub(super) struct ProofSync {
    pub(super) state: Arc<State>,
    pub(super) writer: ProofWriter,
    pub(super) source_rpc: RpcClient,
}

impl ProofSync {
    /// Synchronizes block proofs from an upstream RPC service.
    ///
    /// Proof sync is intentionally coupled to block sync via the committed tip: a proof is only applied
    /// once its block has been committed locally. This means proof sync can stall if block sync falls
    /// behind, but that is acceptable — there is no value in streaming proofs for blocks that have not
    /// yet been applied.
    pub(super) async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // `sync` needs `&mut self` (it commits proofs through the writer capability), so the retry
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
            warn_v2!(err, "Proof sync failed, retrying", retry.delay_ms = RECONNECT_DELAY);
        });

        tokio::select! {
            (_, result) = retry => result,
            () = shutdown.cancelled() => Ok(()),
        }
    }

    pub(super) async fn sync(&mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // Subscribe from next proven tip.
        let starting_block = self.state.proven_tip().child();
        info_v2!("Subscribing to block proof stream", block.from = starting_block);
        let mut client = self.source_rpc.clone();
        let mut stream = client
            .proof_subscription(ProofSubscriptionRequest { block_from: starting_block.as_u32() })
            .await?
            .into_inner();

        let mut expected = starting_block;
        let mut committed_tip_rx = self.state.subscribe_committed_tip();
        loop {
            let result = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = stream.next() => result,
            };
            let Some(result) = result else {
                return Ok(());
            };
            let event = result?.decode_fields().context("failed to decode proof from upstream")?;
            let block_num = BlockNumber::from(event.block_num);

            anyhow::ensure!(
                block_num == expected,
                "upstream sent out-of-sequence proof: expected block {expected}, got {block_num}",
            );

            // Ensure the block is committed before applying its proof so that proven tip never
            // exceeds committed tip.
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = committed_tip_rx.wait_for(|committed_tip| *committed_tip >= block_num) => {
                    result.context("committed tip channel closed")?;
                },
            }

            let proof = event.proof;
            self.writer.apply_proof(block_num, proof.to_bytes()).await?;

            expected = expected.child();
        }
    }
}
