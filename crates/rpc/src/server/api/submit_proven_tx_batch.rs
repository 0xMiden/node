use miden_node_proto::clients::ValidatorClient;
use miden_node_proto::generated as proto;
use miden_node_utils::ErrorReport;
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_tx_batch_prover::LocalBatchProver;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::{Request, Status};
use tracing::Span;

use super::{RpcMode, RpcService};
use crate::server::TrustedSubmission;

pub struct SubmitProvenTxBatchInput {
    request: proto::transaction::TransactionBatch,
    is_authorized_network_tx: bool,
    original_accept_header: Option<MetadataValue<Ascii>>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::SubmitProvenTxBatch for RpcService {
    type Input = SubmitProvenTxBatchInput;
    type Output = proto::blockchain::BlockNumber;

    fn decode(request: proto::transaction::TransactionBatch) -> tonic::Result<Self::Input> {
        Ok(SubmitProvenTxBatchInput {
            request,
            is_authorized_network_tx: false,
            original_accept_header: None,
        })
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn full(
        &self,
        request: Request<proto::transaction::TransactionBatch>,
    ) -> tonic::Result<proto::blockchain::BlockNumber> {
        let is_authorized_network_tx = self.is_authorized_network_tx(request.metadata());
        let original_accept_header = request.metadata().get(http::header::ACCEPT.as_str()).cloned();

        let mut input = Self::decode(request.into_inner())?;
        input.is_authorized_network_tx = is_authorized_network_tx;
        input.original_accept_header = original_accept_header;

        let output = self.handle(input).await?;
        Self::encode(output)
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        let SubmitProvenTxBatchInput {
            request,
            is_authorized_network_tx,
            original_accept_header,
        } = input;

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
        verify_batch_proof(&proven_batch, &proposed_batch).await?;

        match &self.mode {
            RpcMode::Sequencer { block_producer, validator } => {
                submit_batch_to_validator(validator, &proposed_batch, &request.transaction_inputs)
                    .await?;
                block_producer
                    .submit_proven_tx_batch(proposed_batch)
                    .await
                    .map(Into::into)
                    .map_err(Into::into)
            },
            RpcMode::FullNode { source_rpc, trusted, .. } => {
                if let Some(trusted) = trusted {
                    // Trusted full node: validate and authenticate locally, then submit the
                    // authenticated batch to the sequencer's trusted API.
                    self.submit_authenticated_batch_to_sequencer(
                        trusted,
                        proposed_batch,
                        &request.transaction_inputs,
                    )
                    .await
                } else {
                    // Untrusted full node: forward the request to the source verbatim.
                    let mut forwarded_request = Request::new(request);
                    if let Some(accept) = original_accept_header {
                        forwarded_request
                            .metadata_mut()
                            .insert(http::header::ACCEPT.as_str(), accept);
                    }
                    source_rpc
                        .as_ref()
                        .clone()
                        .submit_proven_tx_batch(forwarded_request)
                        .await
                        .map(tonic::Response::into_inner)
                }
            },
        }
    }
}

impl RpcService {
    /// Trusted full-node submission path for a batch.
    ///
    /// Re-executes each transaction via the validator, authenticates each against the
    /// local (replica) store, then submits the authenticated batch to the sequencer's
    /// trusted API.
    async fn submit_authenticated_batch_to_sequencer(
        &self,
        trusted: &TrustedSubmission,
        proposed_batch: ProposedBatch,
        transaction_inputs: &[Vec<u8>],
    ) -> tonic::Result<proto::blockchain::BlockNumber> {
        submit_batch_to_validator(&trusted.validator, &proposed_batch, transaction_inputs).await?;

        let mut auth_inputs = Vec::with_capacity(proposed_batch.transactions().len());
        for tx in proposed_batch.transactions() {
            let inputs = miden_node_block_producer::store::get_tx_inputs(&self.store, tx)
                .await
                .map_err(|err| {
                    Status::internal(err.as_report_context("failed to authenticate transaction"))
                })?;
            auth_inputs.push(inputs.into());
        }

        let authenticated_batch = proto::trusted::AuthenticatedTransactionBatch {
            proposed_batch: proposed_batch.to_bytes(),
            auth_inputs,
        };
        trusted
            .sequencer
            .clone()
            .submit_authenticated_tx_batch(authenticated_batch)
            .await
            .map(tonic::Response::into_inner)
    }
}

/// Verifies the batch proof by re-proving the proposed batch and comparing against the submitted
/// proof.
///
/// Need to do this because `ProvenBatch` has no real kernel yet, so we can only really check that
/// the calculated proof matches the one given in the request.
async fn verify_batch_proof(
    proven_batch: &ProvenBatch,
    proposed_batch: &ProposedBatch,
) -> tonic::Result<()> {
    let expected_proof = spawn_blocking_in_current_span({
        let proposed_batch = proposed_batch.clone();
        move || {
            LocalBatchProver::new(MIN_PROOF_SECURITY_LEVEL)
                .prove(proposed_batch)
                .map_err(|err| {
                    Status::invalid_argument(err.as_report_context("proposed block proof failed"))
                })
        }
    })
    .await
    .map_err(|err| Status::internal(format!("batch proof verification task failed: {err}")))??;

    if &expected_proof != proven_batch {
        return Err(Status::invalid_argument("batch proof did not match proposed batch"));
    }

    Ok(())
}

/// Submits each transaction in the batch to the validator for re-execution.
///
/// The caller must ensure `transaction_inputs` matches the batch's transactions in length and
/// order.
async fn submit_batch_to_validator(
    validator: &ValidatorClient,
    proposed_batch: &ProposedBatch,
    transaction_inputs: &[Vec<u8>],
) -> Result<(), Status> {
    debug_assert_eq!(
        proposed_batch.transactions().len(),
        transaction_inputs.len(),
        "transaction inputs must match the batch's transactions"
    );
    for (tx, inputs) in proposed_batch.transactions().iter().zip(transaction_inputs) {
        let proven_tx = proto::transaction::ProvenTransaction {
            transaction: tx.to_bytes(),
            transaction_inputs: Some(inputs.clone()),
        };
        RpcService::submit_to_validator(validator, &proven_tx).await?;
    }
    Ok(())
}
