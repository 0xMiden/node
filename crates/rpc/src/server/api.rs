use std::num::NonZeroUsize;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{
    BlockProducerClient,
    Builder,
    NtxBuilderClient,
    StoreRpcClient,
    ValidatorClient,
};
use miden_node_proto::decode::{read_account_id, read_account_ids, read_block_range};
use miden_node_proto::domain::account::{AccountRequest, SlotData};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::rpc::MempoolStats;
use miden_node_proto::generated::rpc::api_server::{self, Api};
use miden_node_proto::generated::{self as proto};
use miden_node_proto::try_convert;
use miden_node_utils::ErrorReport;
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNoteTagLimit,
    QueryParamNullifierPrefixLimit,
    QueryParamStorageMapKeyTotalLimit,
};
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::{
    OutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TxAccountUpdate,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, Word};
use miden_tx::TransactionVerifier;
use miden_tx_batch_prover::LocalBatchProver;
use tonic::metadata::MetadataMap;
use tonic::{IntoRequest, Request, Response, Status};
use tracing::{Span, debug, info, info_span};
use url::Url;

use crate::COMPONENT;
use crate::server::NetworkTxAuth;

const NETWORK_TX_AUTH_HEADER_NAME: &str = "x-miden-network-tx-auth";

// RPC SERVICE
// ================================================================================================

pub struct RpcService {
    store: StoreRpcClient,
    block_producer: Option<BlockProducerClient>,
    validator: ValidatorClient,
    ntx_builder: Option<NtxBuilderClient>,
    network_tx_auth: Option<NetworkTxAuth>,
    genesis_commitment: Option<Word>,
    block_commitment_cache: LruCache<BlockNumber, Word>,
}

impl RpcService {
    pub(super) fn new(
        store_url: Url,
        block_producer_url: Option<Url>,
        validator_url: Url,
        ntx_builder_url: Option<Url>,
        commitment_cache_capacity: NonZeroUsize,
        network_tx_auth: Option<NetworkTxAuth>,
    ) -> Self {
        let store = {
            info!(target: COMPONENT, store_endpoint = %store_url, "Initializing store client");
            Builder::new(store_url)
                .without_tls()
                .without_timeout()
                .without_metadata_version()
                .without_metadata_genesis()
                .with_otel_context_injection()
                .connect_lazy::<StoreRpcClient>()
        };

        let block_producer = block_producer_url.map(|block_producer_url| {
            info!(
                target: COMPONENT,
                block_producer_endpoint = %block_producer_url,
                "Initializing block producer client",
            );
            Builder::new(block_producer_url)
                .without_tls()
                .without_timeout()
                .without_metadata_version()
                .without_metadata_genesis()
                .with_otel_context_injection()
                .connect_lazy::<BlockProducerClient>()
        });

        let validator = {
            info!(
                target: COMPONENT,
                validator_endpoint = %validator_url,
                "Initializing validator client",
            );
            Builder::new(validator_url)
                .without_tls()
                .without_timeout()
                .without_metadata_version()
                .without_metadata_genesis()
                .with_otel_context_injection()
                .connect_lazy::<ValidatorClient>()
        };

        let ntx_builder = ntx_builder_url.map(|ntx_builder_url| {
            info!(
                target: COMPONENT,
                ntx_builder_endpoint = %ntx_builder_url,
                "Initializing ntx-builder client",
            );
            Builder::new(ntx_builder_url)
                .without_tls()
                .without_timeout()
                .without_metadata_version()
                .without_metadata_genesis()
                .with_otel_context_injection()
                .connect_lazy::<NtxBuilderClient>()
        });

        Self {
            store,
            block_producer,
            validator,
            ntx_builder,
            network_tx_auth,
            genesis_commitment: None,
            block_commitment_cache: LruCache::new(commitment_cache_capacity),
        }
    }

    /// Sets the genesis commitment, returning an error if it is already set.
    ///
    /// Required since `RpcService::new()` sets up the `store` which is used to fetch the
    /// `genesis_commitment`.
    pub fn set_genesis_commitment(&mut self, commitment: Word) -> anyhow::Result<()> {
        if self.genesis_commitment.is_some() {
            return Err(anyhow::anyhow!("genesis commitment already set"));
        }
        self.genesis_commitment = Some(commitment);
        Ok(())
    }

    /// Fetches the genesis block header from the store.
    ///
    /// Automatically retries until the store connection becomes available.
    pub async fn get_genesis_header_with_retry(&self) -> anyhow::Result<BlockHeader> {
        let mut retry_counter = 0;
        loop {
            let result = self
                .get_block_header_by_number(
                    proto::rpc::BlockHeaderByNumberRequest {
                        block_num: Some(BlockNumber::GENESIS.as_u32()),
                        include_mmr_proof: None,
                    }
                    .into_request(),
                )
                .await;

            match result {
                Ok(header) => {
                    let header = header
                        .into_inner()
                        .block_header
                        .context("response is missing the header")?;
                    let header =
                        BlockHeader::try_from(header).context("failed to parse response")?;

                    return Ok(header);
                },
                Err(err) if err.code() == tonic::Code::Unavailable => {
                    // Exponential backoff with base 500ms and max 30s.
                    let backoff = Duration::from_millis(500)
                        .saturating_mul(1 << retry_counter.min(6))
                        .min(Duration::from_secs(30));

                    tracing::warn!(
                        ?backoff,
                        %retry_counter,
                        %err,
                        "connection failed while fetching genesis header, retrying"
                    );

                    retry_counter += 1;
                    tokio::time::sleep(backoff).await;
                },
                Err(other) => return Err(other.into()),
            }
        }
    }

    /// Returns the given block's onchain commitment.
    ///
    /// This is retrieved from the local LRU cache, or otherwise from the store on cache miss.
    #[tracing::instrument(target = COMPONENT, name = "get_block_commitment", skip_all, fields(block.number = %block))]
    async fn get_block_commitment(&self, block: BlockNumber) -> Result<Word, Status> {
        if let Some(commitment) = self.block_commitment_cache.get(&block) {
            return Ok(commitment);
        }

        let header = self
            .store
            .clone()
            .get_block_header_by_number(Request::new(proto::rpc::BlockHeaderByNumberRequest {
                block_num: Some(block.as_u32()),
                include_mmr_proof: false.into(),
            }))
            .await?
            .into_inner()
            .block_header
            .map(BlockHeader::try_from)
            .transpose()?
            .ok_or_else(|| Status::invalid_argument(format!("unknown block {block}")))?;

        let commitment = header.commitment();
        self.block_commitment_cache.put(block, commitment);

        Ok(commitment)
    }

    /// Returns an error if the provided block's commitment does not match the one on chain.
    async fn verify_reference_commitment(
        &self,
        block: BlockNumber,
        commitment: Word,
    ) -> Result<(), Status> {
        let onchain = self.get_block_commitment(block).await?;

        if onchain != commitment {
            return Err(Status::invalid_argument(format!(
                "reference block's commitment {commitment} at block {block} does not match the chain's commitment of {onchain}",
            )));
        }

        Ok(())
    }

    /// Errors if any of `candidate_ids` is classified as a network account by the store. Callers
    /// should pre-filter to post-deployment, public-account ids; `Ok(())` on empty.
    async fn reject_if_any_network_accounts(
        &self,
        candidate_ids: impl IntoIterator<Item = AccountId>,
    ) -> Result<(), Status> {
        let account_ids: Vec<proto::account::AccountId> =
            candidate_ids.into_iter().map(Into::into).collect();
        if account_ids.is_empty() {
            return Ok(());
        }

        let response = self
            .store
            .clone()
            .filter_network_accounts(tonic::Request::new(proto::account::AccountIdList {
                account_ids,
            }))
            .await
            .map_err(|err| {
                Status::internal(format!("network-account classification failed: {err}"))
            })?;

        if !response.into_inner().account_ids.is_empty() {
            return Err(Status::invalid_argument(
                "Network transactions may not be submitted by users yet",
            ));
        }

        Ok(())
    }

    fn is_authorized_network_tx(&self, metadata: &MetadataMap) -> bool {
        let Some(auth) = &self.network_tx_auth else {
            return false;
        };

        metadata.get(NETWORK_TX_AUTH_HEADER_NAME).is_some_and(|value| value == auth.0)
    }
}

// API IMPLEMENTATION
// ================================================================================================

#[tonic::async_trait]
impl api_server::Api for RpcService {
    type BlockSubscriptionStream = tonic::codec::Streaming<proto::rpc::BlockSubscriptionResponse>;
    type ProofSubscriptionStream = tonic::codec::Streaming<proto::rpc::ProofSubscriptionResponse>;

    // -- Nullifier endpoints -----------------------------------------------------------------

    async fn sync_nullifiers(
        &self,
        request: Request<proto::rpc::SyncNullifiersRequest>,
    ) -> Result<Response<proto::rpc::SyncNullifiersResponse>, Status> {
        let range =
            read_block_range::<Status>(request.get_ref().block_range, "SyncNullifiersRequest")?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);

        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNullifierPrefixLimit>(request.get_ref().nullifiers.len())?;

        self.store.clone().sync_nullifiers(request).await
    }

    // -- Block endpoints ---------------------------------------------------------------------

    async fn get_block_header_by_number(
        &self,
        request: Request<proto::rpc::BlockHeaderByNumberRequest>,
    ) -> Result<Response<proto::rpc::BlockHeaderByNumberResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        Span::current().set_attribute("block.number", request.get_ref().block_num());

        self.store.clone().get_block_header_by_number(request).await
    }

    async fn get_block_by_number(
        &self,
        request: Request<proto::blockchain::BlockRequest>,
    ) -> Result<Response<proto::blockchain::MaybeBlock>, Status> {
        Span::current().set_attribute("block.number", request.get_ref().block_num);

        let request = request.into_inner();

        debug!(target: COMPONENT, ?request);

        self.store.clone().get_block_by_number(request).await
    }

    async fn sync_chain_mmr(
        &self,
        request: Request<proto::rpc::SyncChainMmrRequest>,
    ) -> Result<Response<proto::rpc::SyncChainMmrResponse>, Status> {
        let request_ref = request.get_ref();

        let span = Span::current();
        span.set_attribute("current_client_block_height", request_ref.current_client_block_height);
        span.set_attribute("finality_level", request_ref.finality_level().as_str_name());

        debug!(target: COMPONENT, request = ?request_ref);

        self.store.clone().sync_chain_mmr(request).await
    }

    async fn block_subscription(
        &self,
        request: Request<proto::rpc::BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        let request_ref = request.get_ref();
        Span::current().set_attribute("block.from", request_ref.block_from);

        debug!(target: COMPONENT, request = ?request_ref);

        self.store.clone().block_subscription(request).await
    }

    async fn proof_subscription(
        &self,
        request: Request<proto::rpc::ProofSubscriptionRequest>,
    ) -> Result<Response<Self::ProofSubscriptionStream>, Status> {
        let request_ref = request.get_ref();
        Span::current().set_attribute("block.from", request_ref.block_from);

        debug!(target: COMPONENT, request = ?request_ref);

        self.store.clone().proof_subscription(request).await
    }

    // -- Note endpoints ----------------------------------------------------------------------

    async fn sync_notes(
        &self,
        request: Request<proto::rpc::SyncNotesRequest>,
    ) -> Result<Response<proto::rpc::SyncNotesResponse>, Status> {
        let range = read_block_range::<Status>(request.get_ref().block_range, "SyncNotesRequest")?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);
        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNoteTagLimit>(request.get_ref().note_tags.len())?;

        self.store.clone().sync_notes(request).await
    }

    async fn get_notes_by_id(
        &self,
        request: Request<proto::note::NoteIdList>,
    ) -> Result<Response<proto::note::CommittedNoteList>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNoteIdLimit>(request.get_ref().ids.len())?;

        // Validation checking for correct NoteId's
        let note_ids = request.get_ref().ids.clone();

        let _: Vec<Word> =
            try_convert(note_ids)
                .collect::<Result<_, _>>()
                .map_err(|err: ConversionError| {
                    Status::invalid_argument(err.as_report_context("invalid NoteId"))
                })?;

        self.store.clone().get_notes_by_id(request).await
    }

    async fn get_note_script_by_root(
        &self,
        request: Request<proto::note::NoteScriptRoot>,
    ) -> Result<Response<proto::rpc::MaybeNoteScript>, Status> {
        debug!(target: COMPONENT, request = ?request);

        self.store.clone().get_note_script_by_root(request).await
    }

    // -- Account endpoints -------------------------------------------------------------------

    async fn sync_account_storage_maps(
        &self,
        request: Request<proto::rpc::SyncAccountStorageMapsRequest>,
    ) -> Result<Response<proto::rpc::SyncAccountStorageMapsResponse>, Status> {
        let account_id = read_account_id::<proto::rpc::SyncAccountStorageMapsRequest, Status>(
            request.get_ref().account_id.clone(),
        )?;
        let range = read_block_range::<Status>(
            request.get_ref().block_range,
            "SyncAccountStorageMapsRequest",
        )?;

        let span = Span::current();
        span.set_attribute("account.id", account_id);
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);

        debug!(target: COMPONENT, request = ?request.get_ref());

        self.store.clone().sync_account_storage_maps(request).await
    }

    async fn sync_account_vault(
        &self,
        request: tonic::Request<proto::rpc::SyncAccountVaultRequest>,
    ) -> std::result::Result<tonic::Response<proto::rpc::SyncAccountVaultResponse>, tonic::Status>
    {
        let account_id = read_account_id::<proto::rpc::SyncAccountVaultRequest, Status>(
            request.get_ref().account_id.clone(),
        )?;
        let range =
            read_block_range::<Status>(request.get_ref().block_range, "SyncAccountVaultRequest")?;

        let span = Span::current();
        span.set_attribute("account.id", account_id);
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);

        debug!(target: COMPONENT, request = ?request.get_ref());

        self.store.clone().sync_account_vault(request).await
    }

    /// Validates storage map key limits before forwarding the account request to the store.
    async fn get_account(
        &self,
        raw_request: Request<proto::rpc::AccountRequest>,
    ) -> Result<Response<proto::rpc::AccountResponse>, Status> {
        let raw_request = raw_request.into_inner();
        debug!(target: COMPONENT, ?raw_request);

        let request = AccountRequest::try_from(raw_request.clone())?;

        let span = Span::current();
        span.set_attribute("account.id", request.account_id);
        if let Some(block) = request.block_num {
            span.set_attribute("block.number", block);
        }

        // Validate total storage map key limit before forwarding to store
        if let Some(details) = &request.details {
            let _span = info_span!(target: COMPONENT, "validate_storage_map_keys").entered();
            let total_keys: usize = details
                .storage_requests
                .iter()
                .filter_map(|d| match &d.slot_data {
                    SlotData::All => None,
                    SlotData::MapKeys(items) => Some(items.len()),
                })
                .sum();
            check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;
        }

        self.store.clone().get_account(raw_request).await
    }

    // -- Transaction submission --------------------------------------------------------------

    /// Deserializes and rebuilds the transaction with MAST decorators stripped from output note
    /// scripts, verifies the transaction proof, optionally re-executes via the validator if
    /// transaction inputs are provided, then forwards the transaction to the block producer.
    async fn submit_proven_tx(
        &self,
        request: Request<proto::transaction::ProvenTransaction>,
    ) -> Result<Response<proto::blockchain::BlockNumber>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        let Some(block_producer) = &self.block_producer else {
            return Err(Status::unavailable(
                "Transaction submission not available in read-only mode",
            ));
        };

        let is_authorized_network_tx = self.is_authorized_network_tx(request.metadata());
        let request = request.into_inner();

        let tx = ProvenTransaction::read_from_bytes(&request.transaction).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid transaction"))
        })?;

        let span = Span::current();
        span.set_attribute("transaction.id", tx.id());
        span.set_attribute("account.id", tx.account_id());
        span.set_attribute("transaction.expires_at", tx.expiration_block_num());
        span.set_attribute("transaction.reference_block.number", tx.ref_block_num());
        span.set_attribute("transaction.reference_block.commitment", tx.ref_block_commitment());

        // Verify the reference block is actually part of the chain.
        self.verify_reference_commitment(tx.ref_block_num(), tx.ref_block_commitment())
            .await?;

        // Rebuild a new ProvenTransaction with decorators removed from output notes
        let account_update = TxAccountUpdate::new(
            tx.account_id(),
            tx.account_update().initial_state_commitment(),
            tx.account_update().final_state_commitment(),
            tx.account_update().account_delta_commitment(),
            tx.account_update().details().clone(),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let stripped_outputs = strip_output_note_decorators(tx.output_notes().iter());
        let rebuilt_tx = ProvenTransaction::new(
            account_update,
            tx.input_notes().iter().cloned(),
            stripped_outputs,
            tx.ref_block_num(),
            tx.ref_block_commitment(),
            tx.fee(),
            tx.expiration_block_num(),
            tx.proof().clone(),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut request = request;
        request.transaction = rebuilt_tx.to_bytes();

        // Block post-deployment network-account transactions from user RPC. First-deployment txs
        // are exempt because the protocol-level allowlist only kicks in once the account exists,
        // and network accounts must be public, so private-account txs are filtered out up front.
        //
        // Skip this check if the client is authorized to send network transactions (ntx-builder).
        if !is_authorized_network_tx {
            let candidate_id = (!tx.account_update().initial_state_commitment().is_empty()
                && tx.account_id().is_public())
            .then(|| tx.account_id());
            self.reject_if_any_network_accounts(candidate_id).await?;
        }

        let tx_verifier = TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL);
        tx_verifier.verify(&tx).map_err(|err| {
            Status::invalid_argument(format!(
                "Invalid proof for transaction {}: {}",
                tx.id(),
                err.as_report()
            ))
        })?;

        // Transaction inputs must be provided in order to allow for transaction re-execution via
        // the Validator.
        if request.transaction_inputs.is_some() {
            self.validator.clone().submit_proven_transaction(request.clone()).await?;
        } else {
            return Err(Status::invalid_argument("Transaction inputs must be provided"));
        }

        block_producer.clone().submit_proven_tx(request).await
    }

    /// Deserializes the batch, strips MAST decorators from full output note scripts, rebuilds the
    /// batch, then forwards it to the block producer.
    async fn submit_proven_tx_batch(
        &self,
        request: tonic::Request<proto::transaction::TransactionBatch>,
    ) -> Result<tonic::Response<proto::blockchain::BlockNumber>, Status> {
        let Some(block_producer) = &self.block_producer else {
            return Err(Status::unavailable("Batch submission not available in read-only mode"));
        };

        let is_authorized_network_tx = self.is_authorized_network_tx(request.metadata());
        let request = request.into_inner();

        let proven_batch = ProvenBatch::read_from_bytes(&request.batch_proof).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid proven_batch"))
        })?;

        let span = Span::current();
        span.set_attribute("batch.id", proven_batch.id());
        span.set_attribute("batch.expires_at", proven_batch.batch_expiration_block_num());
        span.set_attribute("batch.reference_block.number", proven_batch.reference_block_num());
        span.set_attribute(
            "batch.reference_block.commitment",
            proven_batch.reference_block_commitment(),
        );

        let proposed_batch = request
            .proposed_batch
            .as_deref()
            .map(ProposedBatch::read_from_bytes)
            .transpose()
            .map_err(|err| {
                Status::invalid_argument(err.as_report_context("invalid proposed_batch"))
            })?
            .ok_or(Status::invalid_argument("missing `proposed_batch` field"))?;

        // Verify the reference block is actually part of the chain.
        self.verify_reference_commitment(
            proven_batch.reference_block_num(),
            proven_batch.reference_block_commitment(),
        )
        .await?;

        // Perform this check here since its cheap. If this passes we can safely zip inputs and
        // transactions.
        if request.transaction_inputs.len() != proposed_batch.transactions().len() {
            return Err(Status::invalid_argument(format!(
                "Number of inputs {} does not match number of transaction {} in batch",
                request.transaction_inputs.len(),
                proposed_batch.transactions().len()
            )));
        }

        // Same gate as `submit_proven_transaction`, applied to every post-deployment tx in the
        // batch. One store round-trip classifies all the non-deployment, public-account ids; any
        // match fails the entire batch.
        //
        // Skip this check if the client is authorized to send network transactions (ntx-builder).
        if !is_authorized_network_tx {
            let non_deployment_ids = proposed_batch
                .transactions()
                .iter()
                .filter(|tx| {
                    !tx.account_update().initial_state_commitment().is_empty()
                        && tx.account_id().is_public()
                })
                .map(|tx| tx.account_id());
            self.reject_if_any_network_accounts(non_deployment_ids).await?;
        }

        // Verify batch transaction proofs.
        //
        // Need to do this because ProvenBatch has no real kernel yet, so we can only
        // really check that the calculated proof matches the one given in the request.
        let expected_proof = LocalBatchProver::new(MIN_PROOF_SECURITY_LEVEL)
            .prove(proposed_batch.clone())
            .map_err(|err| {
                Status::invalid_argument(err.as_report_context("proposed block proof failed"))
            })?;

        if expected_proof != proven_batch {
            return Err(Status::invalid_argument("batch proof did not match proposed batch"));
        }

        // Submit each transaction to the validator.
        //
        // SAFETY: We checked earlier that the two iterators are the same length.
        for (tx, inputs) in proposed_batch.transactions().iter().zip(&request.transaction_inputs) {
            let request = proto::transaction::ProvenTransaction {
                transaction: tx.to_bytes(),
                transaction_inputs: inputs.clone().into(),
            };
            self.validator.clone().submit_proven_transaction(request).await?;
        }

        block_producer.clone().submit_proven_tx_batch(request).await
    }

    // -- Status & utility endpoints ----------------------------------------------------------

    async fn sync_transactions(
        &self,
        request: Request<proto::rpc::SyncTransactionsRequest>,
    ) -> Result<Response<proto::rpc::SyncTransactionsResponse>, Status> {
        let range =
            read_block_range::<Status>(request.get_ref().block_range, "SyncTransactionsRequest")?;
        let n_accounts = request.get_ref().account_ids.len();
        let account_ids =
            read_account_ids::<Status, _>(request.get_ref().account_ids.iter().take(10).cloned())?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);
        span.set_attribute("account.ids", format!("{account_ids:?}").as_str());
        span.set_attribute("account.ids.count", n_accounts);

        debug!(target: COMPONENT, request = ?request);

        check::<QueryParamAccountIdLimit>(request.get_ref().account_ids.len())?;

        self.store.clone().sync_transactions(request).await
    }

    async fn status(
        &self,
        request: Request<()>,
    ) -> Result<Response<proto::rpc::RpcStatus>, Status> {
        debug!(target: COMPONENT, request = ?request);

        let store_status =
            self.store.clone().status(Request::new(())).await.map(Response::into_inner).ok();
        let block_producer_status = if let Some(block_producer) = &self.block_producer {
            block_producer
                .clone()
                .status(Request::new(()))
                .await
                .map(Response::into_inner)
                .ok()
        } else {
            None
        };

        Ok(Response::new(proto::rpc::RpcStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            store: store_status.or(Some(proto::rpc::StoreStatus {
                status: "unreachable".to_string(),
                chain_tip: 0,
                version: "-".to_string(),
            })),
            block_producer: block_producer_status.or(Some(proto::rpc::BlockProducerStatus {
                status: "unreachable".to_string(),
                version: "-".to_string(),
                chain_tip: 0,
                mempool_stats: Some(MempoolStats::default()),
            })),
            genesis_commitment: self.genesis_commitment.map(Into::into),
        }))
    }

    async fn get_limits(
        &self,
        request: Request<()>,
    ) -> Result<Response<proto::rpc::RpcLimits>, Status> {
        debug!(target: COMPONENT, request = ?request);

        Ok(Response::new(RPC_LIMITS.clone()))
    }

    // -- Note debugging endpoints ----------------------------------------------------------------

    async fn get_network_note_status(
        &self,
        request: Request<proto::note::NoteId>,
    ) -> Result<Response<proto::rpc::GetNetworkNoteStatusResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        let Some(ntx_builder) = &self.ntx_builder else {
            return Err(Status::unavailable("Network transaction builder is not enabled"));
        };

        let response = ntx_builder.clone().get_network_note_status(request).await?.into_inner();

        Ok(Response::new(response))
    }
}

// HELPERS
// ================================================================================================

/// Strips decorators from public output notes' scripts.
///
/// This removes MAST decorators from note scripts before forwarding to the block producer,
/// as decorators are not needed for transaction processing.
///
/// Note: `PublicOutputNote::new()` already calls `note.minify_script()` internally, so
/// reconstructing the public note through it handles decorator stripping automatically.
fn strip_output_note_decorators<'a>(
    notes: impl Iterator<Item = &'a OutputNote> + 'a,
) -> impl Iterator<Item = OutputNote> + 'a {
    notes.map(|note| match note {
        OutputNote::Public(public_note) => {
            // Reconstruct via PublicOutputNote::new which calls minify_script() internally.
            let rebuilt = PublicOutputNote::new(public_note.as_note().clone())
                .expect("rebuilding an already-valid public output note should not fail");
            OutputNote::Public(rebuilt)
        },
        OutputNote::Private(header) => OutputNote::Private(header.clone()),
    })
}

// LIMIT HELPERS
// ================================================================================================

/// Formats an "Out of range" error
fn out_of_range_error<E: core::fmt::Display>(err: E) -> Status {
    Status::out_of_range(err.to_string())
}

/// Check, but don't repeat ourselves mapping the error
fn check<Q: QueryParamLimiter>(n: usize) -> Result<(), Status> {
    <Q as QueryParamLimiter>::check(n).map_err(out_of_range_error)
}

/// Helper to build an [`EndpointLimits`](proto::rpc::EndpointLimits) from (name, limit) pairs.
fn endpoint_limits(params: &[(&str, usize)]) -> proto::rpc::EndpointLimits {
    proto::rpc::EndpointLimits {
        parameters: params.iter().map(|(k, v)| ((*k).to_string(), *v as u32)).collect(),
    }
}

/// Cached RPC query parameter limits.
static RPC_LIMITS: LazyLock<proto::rpc::RpcLimits> = LazyLock::new(|| {
    use QueryParamAccountIdLimit as AccountId;
    use QueryParamNoteIdLimit as NoteId;
    use QueryParamNoteTagLimit as NoteTag;
    use QueryParamNullifierPrefixLimit as NullifierPrefix;
    use QueryParamStorageMapKeyTotalLimit as StorageMapKeyTotal;

    proto::rpc::RpcLimits {
        endpoints: std::collections::HashMap::from([
            (
                "SyncNullifiers".into(),
                endpoint_limits(&[(NullifierPrefix::PARAM_NAME, NullifierPrefix::LIMIT)]),
            ),
            (
                "SyncTransactions".into(),
                endpoint_limits(&[(AccountId::PARAM_NAME, AccountId::LIMIT)]),
            ),
            ("SyncNotes".into(), endpoint_limits(&[(NoteTag::PARAM_NAME, NoteTag::LIMIT)])),
            ("GetNotesById".into(), endpoint_limits(&[(NoteId::PARAM_NAME, NoteId::LIMIT)])),
            (
                "GetAccount".into(),
                endpoint_limits(&[(StorageMapKeyTotal::PARAM_NAME, StorageMapKeyTotal::LIMIT)]),
            ),
        ]),
    }
});
