use miden_node_block_producer::store::get_tx_inputs;
use miden_node_proto::clients::{SequencerClient, ValidatorClient};
use miden_node_proto::generated as proto;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{ErrorReport, debug, miden_instrument, miden_span_record, trace};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_tx_batch::BatchVerifier;
use tonic::{Request, Status};

use super::{
    RpcBackend,
    RpcService,
    ensure_transactions_have_fee_notes,
    submit_batch_to_validators,
};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::SubmitProvenTxBatch for RpcService {
    type Input = proto::transaction::TransactionBatch;
    type Output = proto::blockchain::BlockNumber;

    fn decode(request: proto::transaction::TransactionBatch) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "submit_proven_tx_batch",
        err,
    )]
    async fn handle(
        &self,
        input: Self::Input,
        metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let request = input;
        let is_authorized_network_tx = self.is_authorized_network_tx(metadata);
        let original_accept_header = metadata.get(http::header::ACCEPT.as_str()).cloned();

        trace!(
            target: LOG_TARGET,
            "Received transaction batch",
            batch.size = request.sealed_transaction_inputs.len()
        );

        let proven_batch = ProvenBatch::read_from_bytes(&request.batch_proof).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid proven_batch"))
        })?;

        miden_span_record!(
            batch.id = proven_batch.id(),
            batch.expires_at = proven_batch.batch_expiration_block_num(),
            batch.reference_block.number = proven_batch.reference_block_num(),
            batch.reference_block.commitment = proven_batch.reference_block_commitment()
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

        ensure_transactions_have_fee_notes(
            proposed_batch.transactions().iter().map(AsRef::as_ref),
        )?;

        debug!(target: LOG_TARGET, "Submitting transaction batch");

        // Verify the reference block is actually part of the chain.
        self.verify_reference_commitment(
            proven_batch.reference_block_num(),
            proven_batch.reference_block_commitment(),
        )
        .await?;

        // Perform this check here since its cheap. If this passes we can safely zip inputs and
        // transactions.
        if request.sealed_transaction_inputs.len() != proposed_batch.transactions().len() {
            return Err(Status::invalid_argument(format!(
                "Number of inputs {} does not match number of transaction {} in batch",
                request.sealed_transaction_inputs.len(),
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
        verify_batch_proof(proven_batch, &proposed_batch).await?;

        match &self.backend {
            RpcBackend::Sequencer { block_producer, validators } => {
                submit_batch_to_validators(
                    validators.as_slice(),
                    &proposed_batch,
                    &request.sealed_transaction_inputs,
                )
                .await?;
                block_producer
                    .submit_proven_tx_batch(proposed_batch)
                    .await
                    .map(Into::into)
                    .map_err(Into::into)
            },
            RpcBackend::FullNode { pre_auth: Some(pre_auth), .. } => {
                // Pre-authenticated transactions: validate and authenticate locally, then submit
                // the authenticated batch to the sequencer's pre-authenticated API.
                self.submit_authenticated_batch_to_sequencer(
                    pre_auth.validators().as_slice(),
                    pre_auth.sequencer().clone(),
                    proposed_batch,
                    &request.sealed_transaction_inputs,
                )
                .await
            },
            RpcBackend::FullNode { source_rpc, pre_auth: None, .. } => {
                // Unauthenticated transactions: forward the request to the source verbatim.
                let mut forwarded_request = Request::new(request);
                if let Some(accept) = original_accept_header {
                    forwarded_request.metadata_mut().insert(http::header::ACCEPT.as_str(), accept);
                }
                source_rpc
                    .as_ref()
                    .clone()
                    .submit_proven_tx_batch(forwarded_request)
                    .await
                    .map(tonic::Response::into_inner)
            },
        }
    }
}

impl RpcService {
    /// Pre-authenticated transaction submission path for a batch.
    ///
    /// Re-executes each transaction via every validator, authenticates each against the
    /// local (replica) store, then submits the authenticated batch to the sequencer's
    /// pre-authenticated API.
    async fn submit_authenticated_batch_to_sequencer(
        &self,
        validators: &[ValidatorClient],
        mut sequencer: SequencerClient,
        proposed_batch: ProposedBatch,
        sealed_transaction_inputs: &[proto::transaction::SealedTransactionInputs],
    ) -> tonic::Result<proto::blockchain::BlockNumber> {
        submit_batch_to_validators(validators, &proposed_batch, sealed_transaction_inputs).await?;

        let mut auth_inputs = Vec::with_capacity(proposed_batch.transactions().len());
        for tx in proposed_batch.transactions() {
            let inputs = get_tx_inputs(&self.state, tx).await.map_err(|err| {
                Status::internal(err.as_report_context("failed to authenticate transaction"))
            })?;
            auth_inputs.push(inputs.into());
        }

        let authenticated_batch = proto::sequencer::AuthenticatedTransactionBatch {
            proposed_batch: proposed_batch.to_bytes(),
            auth_inputs,
        };
        sequencer
            .submit_authenticated_tx_batch(authenticated_batch)
            .await
            .map(tonic::Response::into_inner)
    }
}

/// Verifies that the provided `proven_batch` is a valid proof for the `proposed_batch`.
///
/// Errors on id mismatch, or the proof cannot be verified [`MIN_PROOF_SECURITY_LEVEL`]
async fn verify_batch_proof(
    proven_batch: ProvenBatch,
    proposed_batch: &ProposedBatch,
) -> tonic::Result<()> {
    if proven_batch.id() != proposed_batch.id() {
        return Err(Status::invalid_argument(format!(
            "batch proof did not match proposed batch in block commitment {}: proven id={}, proposed id={}",
            proposed_batch.reference_block_header().commitment(),
            proven_batch.id(),
            proposed_batch.id()
        )));
    }

    let proven_batch = proven_batch.clone();
    let batch_id = proven_batch.id();
    spawn_blocking_in_current_span(move || {
        BatchVerifier::new(MIN_PROOF_SECURITY_LEVEL)
            .verify(&proven_batch)
            .map_err(|err| {
                Status::invalid_argument(format!(
                    "Invalid proof for batch {}: {}",
                    batch_id,
                    err.as_report()
                ))
            })
    })
    .await
    .map_err(|err| Status::internal(format!("batch proof verification task failed: {err}")))??;

    Ok(())
}
