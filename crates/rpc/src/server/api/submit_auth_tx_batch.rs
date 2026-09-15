use miden_node_block_producer::store::TransactionInputs;
use miden_node_proto::generated::server::sequencer_api;
use miden_node_proto::{DecodeMessage, VerifyWith, generated as proto};
use miden_node_tracing::ErrorReport;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use tonic::Status;

use super::{SequencerInternalService, ensure_transactions_have_fee_notes};

#[tonic::async_trait]
impl sequencer_api::SubmitAuthenticatedTxBatch for SequencerInternalService {
    type Input = proto::sequencer::AuthenticatedTransactionBatch;
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::sequencer::AuthenticatedTransactionBatch,
    ) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let (proof, batch, inputs) =
            spawn_blocking_in_current_span(move || decode_authenticated_transaction_batch(request))
                .await
                .map_err(|err| {
                    Status::internal(format!("authenticated batch decoding task failed: {err}"))
                })??;

        for tx in batch.transactions() {
            self.account_admission.check(tx.account_update()).await?;
        }

        ensure_transactions_have_fee_notes(batch.transactions().iter().map(AsRef::as_ref))?;

        self.block_producer
            .submit_authenticated_tx_batch(proof, batch, inputs)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}

fn decode_authenticated_transaction_batch(
    request: proto::sequencer::AuthenticatedTransactionBatch,
) -> tonic::Result<(ProvenBatch, ProposedBatch, Vec<TransactionInputs>)> {
    let proposed_batch = request
        .proposed_batch
        .ok_or_else(|| Status::invalid_argument("missing `proposed_batch` field"))?;
    let batch = proposed_batch
        .decode_fields()
        .map_err(|err| Status::invalid_argument(format!("invalid proposed_batch: {err}")))?
        .verify_with(miden_protocol::MIN_PROOF_SECURITY_LEVEL)
        .map_err(|err| Status::invalid_argument(format!("invalid proposed_batch: {err}")))?;

    let proof = request
        .batch_proof
        .ok_or_else(|| Status::invalid_argument("missing `batch_proof` field"))?
        .decode_fields()
        .map_err(|err| Status::invalid_argument(format!("invalid batch_proof: {err}")))?
        .verify_with(&batch)
        .map_err(|err| Status::invalid_argument(format!("invalid batch_proof: {err}")))?;

    if batch.transactions().len() != request.auth_inputs.len() {
        return Err(Status::invalid_argument(format!(
            "Number of inputs {} does not match number of transactions {} in batch",
            request.auth_inputs.len(),
            batch.transactions().len()
        )));
    }

    let inputs = request
        .auth_inputs
        .into_iter()
        .map(TransactionInputs::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| Status::invalid_argument(err.as_report_context("invalid auth_inputs")))?;

    Ok((proof, batch, inputs))
}
