use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{BlockProducerClient, Builder, StoreRpcClient, ValidatorClient};
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
    QueryParamNullifierLimit,
    QueryParamStorageMapKeyTotalLimit,
};
use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteRecipient, NoteScript};
use miden_protocol::transaction::{OutputNote, ProvenTransaction, ProvenTransactionBuilder};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, Word};
use miden_tx::TransactionVerifier;
use tonic::{IntoRequest, Request, Response, Status};
use tracing::{debug, info};
use url::Url;

use crate::COMPONENT;

// RPC SERVICE
// ================================================================================================

pub struct RpcService {
    store: StoreRpcClient,
    block_producer: Option<BlockProducerClient>,
    validator: ValidatorClient,
    genesis_commitment: Option<Word>,
}

impl RpcService {
    pub(super) fn new(store_url: Url, block_producer_url: Option<Url>, validator_url: Url) -> Self {
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

        Self {
            store,
            block_producer,
            validator,
            genesis_commitment: None,
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
}

#[tonic::async_trait]
impl api_server::Api for RpcService {
    async fn check_nullifiers(
        &self,
        request: Request<proto::rpc::NullifierList>,
    ) -> Result<Response<proto::rpc::CheckNullifiersResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNullifierLimit>(request.get_ref().nullifiers.len())?;

        // validate all the nullifiers from the user request
        for nullifier in &request.get_ref().nullifiers {
            let _: Word = nullifier
                .try_into()
                .or(Err(Status::invalid_argument("Word field is not in the modulus range")))?;
        }

        self.store.clone().check_nullifiers(request).await
    }

    async fn sync_nullifiers(
        &self,
        request: Request<proto::rpc::SyncNullifiersRequest>,
    ) -> Result<Response<proto::rpc::SyncNullifiersResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamNullifierLimit>(request.get_ref().nullifiers.len())?;

        self.store.clone().sync_nullifiers(request).await
    }

    async fn get_block_header_by_number(
        &self,
        request: Request<proto::rpc::BlockHeaderByNumberRequest>,
    ) -> Result<Response<proto::rpc::BlockHeaderByNumberResponse>, Status> {
        info!(target: COMPONENT, request = ?request.get_ref());

        self.store.clone().get_block_header_by_number(request).await
    }

    async fn sync_state(
        &self,
        request: Request<proto::rpc::SyncStateRequest>,
    ) -> Result<Response<proto::rpc::SyncStateResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        check::<QueryParamAccountIdLimit>(request.get_ref().account_ids.len())?;
        check::<QueryParamNoteTagLimit>(request.get_ref().note_tags.len())?;

        self.store.clone().sync_state(request).await
    }

    async fn sync_account_storage_maps(
        &self,
        request: Request<proto::rpc::SyncAccountStorageMapsRequest>,
    ) -> Result<Response<proto::rpc::SyncAccountStorageMapsResponse>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        self.store.clone().sync_account_storage_maps(request).await
    }

    async fn sync_notes(
        &self,
        request: Request<proto::rpc::SyncNotesRequest>,
    ) -> Result<Response<proto::rpc::SyncNotesResponse>, Status> {
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

    async fn sync_account_vault(
        &self,
        request: tonic::Request<proto::rpc::SyncAccountVaultRequest>,
    ) -> std::result::Result<tonic::Response<proto::rpc::SyncAccountVaultResponse>, tonic::Status>
    {
        debug!(target: COMPONENT, request = ?request.get_ref());

        self.store.clone().sync_account_vault(request).await
    }

    async fn submit_proven_transaction(
        &self,
        request: Request<proto::transaction::ProvenTransaction>,
    ) -> Result<Response<proto::blockchain::BlockNumber>, Status> {
        debug!(target: COMPONENT, request = ?request.get_ref());

        let Some(block_producer) = &self.block_producer else {
            return Err(Status::unavailable(
                "Transaction submission not available in read-only mode",
            ));
        };

        let request = request.into_inner();

        let tx = ProvenTransaction::read_from_bytes(&request.transaction).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid transaction"))
        })?;

        // Rebuild a new ProvenTransaction with decorators removed from output notes
        let mut builder = ProvenTransactionBuilder::new(
            tx.account_id(),
            tx.account_update().initial_state_commitment(),
            tx.account_update().final_state_commitment(),
            tx.account_update().account_delta_commitment(),
            tx.ref_block_num(),
            tx.ref_block_commitment(),
            tx.fee(),
            tx.expiration_block_num(),
            tx.proof().clone(),
        )
        .account_update_details(tx.account_update().details().clone())
        .add_input_notes(tx.input_notes().iter().cloned());

        let stripped_outputs = tx.output_notes().iter().map(|note| match note {
            OutputNote::Full(note) => {
                let mut mast = note.script().mast().clone();
                Arc::make_mut(&mut mast).strip_decorators();
                let script = NoteScript::from_parts(mast, note.script().entrypoint());
                let recipient =
                    NoteRecipient::new(note.serial_num(), script, note.storage().clone());
                let new_note = Note::new(note.assets().clone(), note.metadata().clone(), recipient);
                OutputNote::Full(new_note)
            },
            other => other.clone(),
        });
        builder = builder.add_output_notes(stripped_outputs);
        let rebuilt_tx = builder.build().map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut request = request;
        request.transaction = rebuilt_tx.to_bytes();

        // Only allow deployment transactions for new network accounts
        if tx.account_id().is_network()
            && !tx.account_update().initial_state_commitment().is_empty()
        {
            return Err(Status::invalid_argument(
                "Network transactions may not be submitted by users yet",
            ));
        }

        let tx_verifier = TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL);

        tx_verifier.verify(&tx).map_err(|err| {
            Status::invalid_argument(format!(
                "Invalid proof for transaction {}: {}",
                tx.id(),
                err.as_report()
            ))
        })?;

        // If transaction inputs are provided, re-execute the transaction to validate it.
        if request.transaction_inputs.is_some() {
            // Re-execute the transaction via the Validator.
            self.validator.clone().submit_proven_transaction(request.clone()).await?;
        }

        block_producer.clone().submit_proven_transaction(request).await
    }

    async fn submit_proven_batch(
        &self,
        request: tonic::Request<proto::transaction::ProvenTransactionBatch>,
    ) -> Result<tonic::Response<proto::blockchain::BlockNumber>, Status> {
        let Some(block_producer) = &self.block_producer else {
            return Err(Status::unavailable("Batch submission not available in read-only mode"));
        };

        let mut request = request.into_inner();

        let batch = ProvenBatch::read_from_bytes(&request.encoded)
            .map_err(|err| Status::invalid_argument(err.as_report_context("invalid batch")))?;

        // Build a new batch with output notes' decorators removed
        let stripped_outputs: Vec<OutputNote> = batch
            .output_notes()
            .iter()
            .map(|note| match note {
                OutputNote::Full(note) => {
                    let mut mast = note.script().mast().clone();
                    Arc::make_mut(&mut mast).strip_decorators();
                    let script = NoteScript::from_parts(mast, note.script().entrypoint());
                    let recipient =
                        NoteRecipient::new(note.serial_num(), script, note.storage().clone());
                    let new_note =
                        Note::new(note.assets().clone(), note.metadata().clone(), recipient);
                    OutputNote::Full(new_note)
                },
                other => other.clone(),
            })
            .collect();

        let rebuilt_batch = ProvenBatch::new(
            batch.id(),
            batch.reference_block_commitment(),
            batch.reference_block_num(),
            batch.account_updates().clone(),
            batch.input_notes().clone(),
            stripped_outputs,
            batch.batch_expiration_block_num(),
            batch.transactions().clone(),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

        request.encoded = rebuilt_batch.to_bytes();

        // Only allow deployment transactions for new network accounts
        for tx in batch.transactions().as_slice() {
            if tx.account_id().is_network() && !tx.initial_state_commitment().is_empty() {
                return Err(Status::invalid_argument(
                    "Network transactions may not be submitted by users yet",
                ));
            }
        }

        block_producer.clone().submit_proven_batch(request).await
    }

    async fn get_block_by_number(
        &self,
        request: Request<proto::blockchain::BlockNumber>,
    ) -> Result<Response<proto::blockchain::MaybeBlock>, Status> {
        let request = request.into_inner();

        debug!(target: COMPONENT, ?request);

        self.store.clone().get_block_by_number(request).await
    }

    async fn get_account(
        &self,
        request: Request<proto::rpc::AccountRequest>,
    ) -> Result<Response<proto::rpc::AccountResponse>, Status> {
        use proto::rpc::account_request::account_detail_request::storage_map_detail_request::{
            SlotData::MapKeys as ProtoMapKeys,
            SlotData::AllEntries as ProtoMapAllEntries
        };

        let request = request.into_inner();

        debug!(target: COMPONENT, ?request);

        // Validate total storage map key limit before forwarding to store
        if let Some(details) = &request.details {
            let total_keys: usize = details
                .storage_maps
                .iter()
                .filter_map(|m| m.slot_data.as_ref())
                .filter_map(|d| match d {
                    ProtoMapKeys(keys) => Some(keys.map_keys.len()),
                    ProtoMapAllEntries(_) => None,
                })
                .sum();
            check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;
        }

        self.store.clone().get_account(request).await
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

    async fn get_note_script_by_root(
        &self,
        request: Request<proto::note::NoteRoot>,
    ) -> Result<Response<proto::rpc::MaybeNoteScript>, Status> {
        debug!(target: COMPONENT, request = ?request);

        self.store.clone().get_note_script_by_root(request).await
    }

    async fn sync_transactions(
        &self,
        request: Request<proto::rpc::SyncTransactionsRequest>,
    ) -> Result<Response<proto::rpc::SyncTransactionsResponse>, Status> {
        debug!(target: COMPONENT, request = ?request);

        self.store.clone().sync_transactions(request).await
    }

    async fn get_limits(
        &self,
        request: Request<()>,
    ) -> Result<Response<proto::rpc::RpcLimits>, Status> {
        debug!(target: COMPONENT, request = ?request);

        Ok(Response::new(RPC_LIMITS.clone()))
    }
}

// LIMIT HELPERS
// ================================================================================================

/// Formats an "Out of range" error
fn out_of_range_error<E: core::fmt::Display>(err: E) -> Status {
    Status::out_of_range(err.to_string())
}

/// Check, but don't repeat ourselves mapping the error
#[allow(clippy::result_large_err)]
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
    use {
        QueryParamAccountIdLimit as AccountId,
        QueryParamNoteIdLimit as NoteId,
        QueryParamNoteTagLimit as NoteTag,
        QueryParamNullifierLimit as Nullifier,
        QueryParamStorageMapKeyTotalLimit as StorageMapKeyTotal,
    };

    proto::rpc::RpcLimits {
        endpoints: std::collections::HashMap::from([
            (
                "CheckNullifiers".into(),
                endpoint_limits(&[(Nullifier::PARAM_NAME, Nullifier::LIMIT)]),
            ),
            (
                "SyncNullifiers".into(),
                endpoint_limits(&[(Nullifier::PARAM_NAME, Nullifier::LIMIT)]),
            ),
            (
                "SyncState".into(),
                endpoint_limits(&[
                    (AccountId::PARAM_NAME, AccountId::LIMIT),
                    (NoteTag::PARAM_NAME, NoteTag::LIMIT),
                ]),
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
