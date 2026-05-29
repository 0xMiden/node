use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use miden_crypto::utils::Deserializable;
use miden_node_proto::generated::rpc::{
    BlockSubscriptionRequest,
    ProofSubscriptionRequest,
    api_client,
};
use miden_node_utils::retry::{self, Retryable};
use miden_protocol::block::{BlockNumber, SignedBlock};
use tokio_stream::StreamExt;
use tracing::{info, warn};
use url::Url;

use crate::state::{Finality, State};

pub(crate) const RECONNECT_DELAY: Duration = Duration::from_secs(5);

type RpcClient = api_client::ApiClient<tonic::transport::Channel>;

// REPLICA SYNC
// ================================================================================================

/// Shared reconnect-loop scaffolding for replica client types.
///
/// Implementors provide [`SYNC_KIND`](ReplicaSync::SYNC_KIND),
/// [`upstream_url`](ReplicaSync::upstream_url), and [`subscribe`](ReplicaSync::subscribe). The
/// default [`sync`](ReplicaSync::sync) opens the upstream connection and passes the client to
/// `subscribe`; [`run`](ReplicaSync::run) and [`spawn`](ReplicaSync::spawn) wrap `sync` in an
/// infinite reconnect loop.
#[async_trait]
pub(crate) trait ReplicaSync: Sized + Send + Sync + 'static {
    /// Short label used in log messages, e.g. `"Block"` or `"Proof"`.
    const SYNC_KIND: &'static str;

    /// Returns the upstream RPC URL to connect to.
    fn upstream_url(&self) -> &Url;

    /// Subscribes to the upstream stream via `client` and processes events until the stream ends or
    /// an error occurs.
    async fn subscribe(&self, client: RpcClient) -> anyhow::Result<()>;

    /// Opens a connection to [`upstream_url`](Self::upstream_url) and calls
    /// [`subscribe`](Self::subscribe) with the resulting client.
    async fn sync(&self) -> anyhow::Result<()> {
        let channel = tonic::transport::Channel::from_shared(self.upstream_url().to_string())?
            .connect()
            .await?;
        self.subscribe(RpcClient::new(channel)).await
    }

    /// Runs [`sync`](Self::sync) in an infinite loop, sleeping [`RECONNECT_DELAY`] on failure.
    ///
    /// A successful end-of-stream is treated as a failure so the connection is always re-opened.
    async fn run(self) -> anyhow::Result<()> {
        (|| async {
            self.sync()
                .await
                .and_then(|()| Err(anyhow::anyhow!("unexpected end of stream")))
        })
        .retry(retry::constant(RECONNECT_DELAY, None))
        .notify(|err, _| {
            warn!(
                err = %format!("{err:#}"),
                retry.delay = %RECONNECT_DELAY.as_secs(),
                "{} sync failed, retrying",
                Self::SYNC_KIND
            );
        })
        .await
    }

    /// Spawns [`run`](Self::run) as a Tokio task.
    fn spawn(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(self.run())
    }
}

// BLOCK REPLICA SYNC
// ================================================================================================

/// Subscribes to blocks from an upstream RPC service and applies them locally.
pub struct BlockReplicaSync {
    state: Arc<State>,
    upstream_url: Url,
}

impl BlockReplicaSync {
    pub fn new(state: Arc<State>, upstream_url: Url) -> Self {
        Self { state, upstream_url }
    }
}

#[async_trait]
impl ReplicaSync for BlockReplicaSync {
    const SYNC_KIND: &'static str = "Block";

    fn upstream_url(&self) -> &Url {
        &self.upstream_url
    }

    async fn subscribe(&self, mut client: RpcClient) -> anyhow::Result<()> {
        let block_from = self.state.chain_tip(Finality::Committed).await.child().as_u32();
        info!(block_from, upstream_url = %self.upstream_url, "Connecting to upstream RPC for blocks");

        let mut stream = client
            .block_subscription(BlockSubscriptionRequest { block_from })
            .await?
            .into_inner();

        while let Some(result) = stream.next().await {
            let event = result?;
            let block = SignedBlock::read_from_bytes(&event.block)
                .context("failed to deserialize block from upstream")?;
            self.state.apply_block(block).await?;
        }

        Ok(())
    }
}

// PROOF REPLICA SYNC
// ================================================================================================

/// Subscribes to proofs from an upstream RPC service and applies them locally.
pub struct ProofReplicaSync {
    state: Arc<State>,
    upstream_url: Url,
}

impl ProofReplicaSync {
    pub fn new(state: Arc<State>, upstream_url: Url) -> Self {
        Self { state, upstream_url }
    }
}

#[async_trait]
impl ReplicaSync for ProofReplicaSync {
    const SYNC_KIND: &'static str = "Proof";

    fn upstream_url(&self) -> &Url {
        &self.upstream_url
    }

    async fn subscribe(&self, mut client: RpcClient) -> anyhow::Result<()> {
        let block_from = self.state.chain_tip(Finality::Proven).await.as_u32().saturating_add(1);
        info!(block_from, upstream_url = %self.upstream_url, "Connecting to upstream RPC for proofs");

        let mut stream = client
            .proof_subscription(ProofSubscriptionRequest { block_from })
            .await?
            .into_inner();

        while let Some(result) = stream.next().await {
            let event = result?;
            let block_num = BlockNumber::from(event.block_num);
            self.state.apply_proof(block_num, event.proof).await?;
        }

        Ok(())
    }
}
