//! Node access. The RPC handling is copied from the network monitor.

use std::time::Duration;

use anyhow::{Context, Result};
use backon::ExponentialBuilder;
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::domain::account::{AccountResponse, AccountVaultDetails};
use miden_node_proto::generated::rpc::account_request::AccountDetailRequest;
use miden_node_proto::generated::rpc::{
    AccountRequest as ProtoAccountRequest,
    BlockHeaderByNumberRequest,
};
use miden_node_tracing::warn;
use miden_node_utils::retry::Retryable;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetVault;
use miden_protocol::block::{BlockHeader, BlockNumber, FeeParameters};
use url::Url;

use crate::COMPONENT;

// RPC NODE CLIENT
// ================================================================================================

/// Reads chain state from the node's RPC API.
#[derive(Clone)]
pub struct RpcNodeClient {
    rpc_client: RpcClient,
    genesis_commitment: Word,
}

impl RpcNodeClient {
    /// Connects to the node's RPC API.
    pub async fn connect(rpc_url: &Url, timeout: Duration) -> Result<Self> {
        let (rpc_client, genesis_commitment) =
            create_genesis_aware_rpc_client(rpc_url, timeout).await?;

        Ok(Self { rpc_client, genesis_commitment })
    }

    /// The commitment of the genesis block the node serves. It identifies the chain.
    pub fn genesis_commitment(&self) -> Word {
        self.genesis_commitment
    }

    /// The fee parameters of `block_num`, or at the chain tip when it is `None`.
    pub async fn fee_parameters(&self, block_num: Option<BlockNumber>) -> Result<FeeParameters> {
        let header = fetch_block_header(&mut self.rpc_client.clone(), block_num).await?;

        Ok(header.fee_parameters().clone())
    }

    /// The asset vault of a public account, with the block number the node observed it at.
    pub async fn public_account_vault(
        &self,
        account_id: AccountId,
    ) -> Result<(AssetVault, BlockNumber)> {
        let id_bytes: [u8; 15] = account_id.into();
        // A dummy commitment never matches the vault root, which makes the node return the vault in
        // full. Code and storage are not requested.
        let dummy = Word::default().into();
        let request = ProtoAccountRequest {
            account_id: Some(miden_node_proto::generated::account::AccountId {
                id: id_bytes.to_vec(),
            }),
            // Without a block number the node answers at its chain tip.
            block_num: None,
            details: Some(AccountDetailRequest {
                code_commitment: None,
                asset_vault_commitment: Some(dummy),
                storage_request: None,
            }),
        };

        let response = self
            .rpc_client
            .clone()
            .get_account(request)
            .await
            .with_context(|| format!("failed to fetch account {account_id}"))?
            .into_inner();
        let response = AccountResponse::try_from(response)
            .context("failed to convert the account response")?;

        let details = response
            .details
            .with_context(|| format!("no details returned for public account {account_id}"))?;

        let vault = match details.vault_details {
            AccountVaultDetails::Assets(assets) => {
                AssetVault::new(&assets).context("failed to build the vault")?
            },
            AccountVaultDetails::LimitExceeded => {
                anyhow::bail!("account {account_id} holds too many assets to fetch in full")
            },
        };

        Ok((vault, response.block_num))
    }
}

// RPC HELPERS
// ================================================================================================

/// Backoff for the genesis-discovery handshake, so a node which is still starting does not abort
/// the service.
const GENESIS_DISCOVERY_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const GENESIS_DISCOVERY_BACKOFF_MAX: Duration = Duration::from_secs(30);
const GENESIS_DISCOVERY_MAX_RETRIES: usize = 10;

fn genesis_discovery_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(GENESIS_DISCOVERY_BACKOFF_INITIAL)
        .with_max_delay(GENESIS_DISCOVERY_BACKOFF_MAX)
        .with_factor(2.0)
        .with_max_times(GENESIS_DISCOVERY_MAX_RETRIES)
        .with_jitter()
}

/// Creates an RPC client configured with the correct genesis metadata in the `Accept` header so
/// that write RPCs such as `SubmitProvenTx` are accepted by the node.
async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<(RpcClient, Word)> {
    (|| async {
        // First, create a temporary client without genesis metadata to discover the genesis block
        // header and its commitment.
        let mut rpc: RpcClient = Builder::new(rpc_url.clone())
            .with_tls()
            .context("failed to configure TLS for the RPC client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect()
            .await
            .context("failed to create an RPC client for genesis discovery")?;

        let genesis_header = fetch_block_header(&mut rpc, Some(BlockNumber::GENESIS)).await?;
        let genesis_commitment = genesis_header.commitment();

        // Rebuild the client, this time including the required genesis metadata so that write RPCs
        // like SubmitProvenTx are accepted by the node.
        let rpc_client = Builder::new(rpc_url.clone())
            .with_tls()
            .context("failed to configure TLS for the RPC client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .with_metadata_genesis(genesis_commitment)
            .without_auth_header()
            .with_otel_context_injection()
            .connect()
            .await
            .context("failed to connect to the RPC server with genesis metadata")?;

        Ok((rpc_client, genesis_commitment))
    })
    .retry(genesis_discovery_backoff())
    .notify(|err: &anyhow::Error, sleep: Duration| {
        warn!(
            err,
            target: COMPONENT,
            "RPC genesis discovery failed; retrying after backoff",
            retry.delay_ms = sleep.as_millis() as u64
        );
    })
    .await
}

/// Fetches a block header from RPC.
async fn fetch_block_header(
    rpc_client: &mut RpcClient,
    block_num: Option<BlockNumber>,
) -> Result<BlockHeader> {
    let request = BlockHeaderByNumberRequest {
        block_num: block_num.map(|block_num| block_num.as_u32()),
        include_mmr_proof: None,
    };

    let response = rpc_client
        .get_block_header_by_number(request)
        .await
        .context("failed to get the block header from RPC")?;

    let block_header = response
        .into_inner()
        .block_header
        .context("the block header response holds no header")?;

    block_header.try_into().context("failed to convert the block header")
}
