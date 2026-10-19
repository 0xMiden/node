//! Node access.

use std::error::Error as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use backon::ExponentialBuilder;
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::domain::encryption::{
    TransactionInputsSealer,
    TrustedTransactionEncryptionState,
};
use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use miden_node_proto::generated::miden::node::v1::{
    BlockRange,
    FinalityLevel,
    GetBlockHeaderByNumberRequest,
    SyncChainMmrRequest,
    SyncTransactionsRequest,
};
use miden_node_proto::generated::submission::ProvenTransactionSubmission;
use miden_node_proto::{DecodeMessageExt, VerifyWith};
use miden_node_tracing::{
    ErrorSpanExt,
    Level,
    Span,
    enabled,
    miden_instrument,
    miden_span_record,
    warn,
};
use miden_node_utils::retry::Retryable;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrPeaks, PartialMmr};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, ProvenTransaction, TransactionId};
use tokio::sync::Mutex;
use url::Url;

use crate::COMPONENT;

#[cfg(test)]
pub(crate) mod tests;

// RPC NODE CLIENT
// ================================================================================================

/// Reads chain state from the node's RPC API and submits transactions to it.
#[derive(Clone)]
pub struct RpcNodeClient {
    rpc_client: RpcClient,
    genesis_commitment: Word,
    protocol_config: ProtocolConfig,
    trusted_validator_signing_keys: Arc<[ValidatorPublicKey]>,
    sealer: Arc<Mutex<Option<TransactionInputsSealer>>>,
}

impl RpcNodeClient {
    /// Connects to the node's RPC API and verifies the attested transaction encryption key.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.node.connect",
        err,
    )]
    pub async fn connect(
        rpc_url: &Url,
        timeout: Duration,
        trusted_validator_signing_keys: Vec<ValidatorPublicKey>,
    ) -> Result<Self> {
        anyhow::ensure!(
            !trusted_validator_signing_keys.is_empty(),
            "at least one trusted validator signing key is required to verify the transaction \
             encryption key",
        );

        let (rpc_client, genesis_commitment, protocol_config) =
            create_genesis_aware_rpc_client(rpc_url, timeout).await?;

        let client = Self {
            rpc_client,
            genesis_commitment,
            protocol_config,
            trusted_validator_signing_keys: Arc::from(trusted_validator_signing_keys),
            sealer: Arc::new(Mutex::new(None)),
        };
        // Fetch and verify the encryption key eagerly so an untrusted key fails at startup.
        client.sealer().await?;

        Ok(client)
    }

    /// The commitment of the genesis block the node serves. It identifies the chain.
    pub fn genesis_commitment(&self) -> Word {
        self.genesis_commitment
    }

    /// The protocol configuration the genesis block commits to.
    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// The committed chain tip header with a partial blockchain which proves it.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.node.tip_chain_state",
        err,
    )]
    pub async fn tip_chain_state(&self) -> Result<(BlockHeader, PartialBlockchain)> {
        fetch_tip_chain_state(&mut self.rpc_client.clone(), self.genesis_commitment).await
    }

    /// Returns an RPC connection to the node.
    pub fn rpc_client(&self) -> RpcClient {
        self.rpc_client.clone()
    }

    /// Checks for commitment before reporting expiration. Reads every page in the block range.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.node.transaction_status",
        level = "debug",
        fields(
            account.id = account_id,
            transaction.id = transaction_id,
            block_range.from = reference_block,
            block_range.to = expiration_block,
        ),
        err(level = "debug"),
    )]
    pub async fn transaction_status(
        &self,
        account_id: AccountId,
        transaction_id: TransactionId,
        reference_block: BlockNumber,
        expiration_block: BlockNumber,
    ) -> Result<TransactionStatus> {
        let tip = self.committed_tip().await?;
        let end = tip.min(expiration_block);
        let mut start = reference_block + 1;
        let mut pages = 0_usize;
        if enabled!(target: COMPONENT, Level::DEBUG) {
            miden_span_record!(tip.number = tip);
        }

        while start <= end {
            let response = self
                .rpc_client
                .clone()
                .sync_transactions(SyncTransactionsRequest {
                    block_range: Some(BlockRange {
                        block_from: start.as_u32(),
                        block_to: end.as_u32(),
                    }),
                    account_ids: vec![account_id.into()],
                })
                .await
                .context("failed to synchronize transactions")?
                .into_inner();

            pages += 1;
            for record in response.transactions {
                let id = record
                    .header
                    .context("a transaction record did not include a header")?
                    .transaction_id
                    .context("a transaction header did not include an ID")?
                    .decode_and_verify()
                    .context("failed to convert a transaction ID")?;
                if id == transaction_id {
                    if enabled!(target: COMPONENT, Level::DEBUG) {
                        miden_span_record!(page.count = pages);
                    }
                    return Ok(TransactionStatus::Committed);
                }
            }

            let last_checked: BlockNumber = response
                .pagination_info
                .context("the sync_transactions response did not include pagination information")?
                .block_num
                .into();
            anyhow::ensure!(
                (start..=end).contains(&last_checked),
                "the node answered a transaction scan from {start} to {end} with block {last_checked}",
            );
            if last_checked == end {
                break;
            }
            start = last_checked + 1;
        }

        if enabled!(target: COMPONENT, Level::DEBUG) {
            miden_span_record!(page.count = pages);
        }
        Ok(if tip >= expiration_block {
            TransactionStatus::Expired
        } else {
            TransactionStatus::Pending
        })
    }

    /// The chain tip of the node's local store.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.node.committed_tip",
        level = "debug",
        err(level = "debug"),
    )]
    pub async fn committed_tip(&self) -> Result<BlockNumber> {
        let status = self
            .rpc_client
            .clone()
            .status(miden_node_proto::generated::miden::node::v1::StatusRequest {})
            .await
            .context("failed to fetch the node status")?
            .into_inner();

        Ok(status.chain_tip.into())
    }

    /// Seals and submits one proven transaction. Errors occur before submission starts.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.node.submit",
        fields(
            transaction.id = proven_tx.id(),
        ),
        err,
    )]
    pub async fn submit(
        &self,
        proven_tx: &ProvenTransaction,
        transaction_inputs: &[u8],
    ) -> Result<SubmissionOutcome> {
        let sealed = self
            .sealer()
            .await?
            .seal(proven_tx.id(), transaction_inputs)
            .context("failed to seal the transaction inputs")?;
        let request = ProvenTransactionSubmission {
            transaction: Some(proven_tx.into()),
            sealed_transaction_inputs: Some(sealed),
        };
        let result = self
            .rpc_client
            .clone()
            .submit_proven_tx(miden_node_proto::generated::miden::node::v1::SubmitProvenTxRequest {
                submission: Some(request),
            })
            .await;

        if result.is_err() {
            // The encryption key can be stale. Fetch it again for the next submission.
            *self.sealer.lock().await = None;
        }

        let outcome = match result {
            Ok(_) => SubmissionOutcome::Accepted,
            Err(status) => {
                Span::current().set_error(&status);
                warn!(&status, target: COMPONENT, "Funding transaction submission failed");
                miden_span_record!(rpc.status = status.code().to_string() #[nonstandard]);
                SubmissionOutcome::from_status(status)
            },
        };
        miden_span_record!(funding.submission_outcome = outcome.as_str() #[nonstandard]);
        Ok(outcome)
    }

    /// The cached verified sealer. The attested key is fetched and checked on first use.
    async fn sealer(&self) -> Result<TransactionInputsSealer> {
        if let Some(sealer) = self.sealer.lock().await.clone() {
            return Ok(sealer);
        }

        self.refresh_sealer().await
    }

    /// Fetches and verifies the node's transaction encryption key on a cache miss.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.node.refresh_sealer",
        err,
    )]
    async fn refresh_sealer(&self) -> Result<TransactionInputsSealer> {
        let key = self
            .rpc_client
            .clone()
            .get_transaction_encryption_key(
                miden_node_proto::generated::miden::node::v1::GetTransactionEncryptionKeyRequest {},
            )
            .await
            .context("failed to fetch the transaction encryption key")?
            .into_inner()
            .key
            .ok_or_else(|| tonic::Status::internal("missing transaction encryption key"))?;
        let verified = key
            .verify_with(TrustedTransactionEncryptionState::new(
                self.genesis_commitment,
                &self.trusted_validator_signing_keys,
            ))
            .context("untrusted transaction encryption key")?;
        let sealer = TransactionInputsSealer::new(verified);

        let mut cached = self.sealer.lock().await;
        if let Some(sealer) = cached.clone() {
            return Ok(sealer);
        }
        *cached = Some(sealer.clone());
        Ok(sealer)
    }
}

/// Whether the node accepted, rejected, or might have received the submission.
#[derive(Debug)]
pub enum SubmissionOutcome {
    Accepted,
    Rejected(tonic::Status),
    Unknown(tonic::Status),
}

impl SubmissionOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected(_) => "rejected",
            Self::Unknown(_) => "unknown",
        }
    }

    fn from_status(status: tonic::Status) -> Self {
        // The error byte identifies a node rejection. Without it, these codes can also report
        // transport or response-decoding failures after the node accepted the transaction.
        let unknown = status.source().is_some()
            || (status.details().len() != 1
                && matches!(
                    status.code(),
                    tonic::Code::Cancelled
                        | tonic::Code::Unknown
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::Internal
                        | tonic::Code::Unavailable
                        | tonic::Code::DataLoss
                ));
        if unknown {
            Self::Unknown(status)
        } else {
            Self::Rejected(status)
        }
    }
}

/// The outcome of a transaction at the committed chain tip.
#[derive(Debug, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Committed,
    Expired,
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
) -> Result<(RpcClient, Word, ProtocolConfig)> {
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

        let (genesis_header, protocol_config) = fetch_genesis_header_and_config(&mut rpc).await?;
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

        Ok((rpc_client, genesis_commitment, protocol_config))
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

/// Fetches the genesis block header and the protocol configuration it commits to.
///
/// The commitment of the returned configuration is checked against the header, so a configuration
/// which names an asset the chain does not use is rejected.
async fn fetch_genesis_header_and_config(
    rpc_client: &mut RpcClient,
) -> Result<(BlockHeader, ProtocolConfig)> {
    let response = rpc_client
        .get_block_header_by_number(GetBlockHeaderByNumberRequest {
            block_num: Some(BlockNumber::GENESIS.as_u32()),
            include_mmr_proof: None,
            include_protocol_config: Some(true),
        })
        .await
        .context("failed to get the genesis block header from RPC")?
        .into_inner();

    let block_header: BlockHeader = response
        .block_header
        .context("the block header response holds no header")?
        .decode_and_build_unchecked()
        .context("failed to build the block header")?;

    let protocol_config = ensure_protocol_config_is_present_and_matches_header(
        response.protocol_config,
        &block_header,
    )
    .context("the node served an invalid protocol configuration")?;

    Ok((block_header, protocol_config))
}

/// Fetches the chain tip header together with a [`PartialBlockchain`] whose peaks hash to that
/// header's chain commitment, making the pair usable as a transaction reference block.
async fn fetch_tip_chain_state(
    rpc_client: &mut RpcClient,
    genesis_commitment: Word,
) -> Result<(BlockHeader, PartialBlockchain)> {
    let response = rpc_client
        .sync_chain_mmr(SyncChainMmrRequest {
            // The MMR is seeded with the genesis block below, so the delta starts at block 1.
            current_client_block_height: BlockNumber::GENESIS.as_u32(),
            finality_level: FinalityLevel::Committed.into(),
        })
        .await
        .context("failed to sync the chain MMR")?
        .into_inner();

    let tip_header: BlockHeader = response
        .block_header
        .context("the sync_chain_mmr response did not include a block header")?
        .decode_and_build_unchecked()
        .context("failed to build the sync target block header")?;

    let delta: MmrDelta = response
        .mmr_delta
        .context("the sync_chain_mmr response did not include an MMR delta")?
        .decode_and_verify()
        .context("failed to verify the MMR delta")?;

    let mut mmr = PartialMmr::from_peaks(
        MmrPeaks::new(Forest::new(0).context("an empty forest should be valid")?, Vec::new())
            .context("empty MMR peaks should be valid")?,
    );

    if tip_header.block_num() != BlockNumber::GENESIS {
        mmr.add(genesis_commitment, false)
            .context("failed to seed the MMR with the genesis block")?;
        mmr.apply(delta).context("failed to apply the MMR delta")?;
    }

    anyhow::ensure!(
        mmr.peaks().hash_peaks() == tip_header.chain_commitment(),
        "the synced MMR peaks do not match the chain commitment of block {}",
        tip_header.block_num()
    );

    let blockchain = PartialBlockchain::new(mmr, Vec::new())
        .context("failed to build the partial blockchain")?;

    Ok((tip_header, blockchain))
}
