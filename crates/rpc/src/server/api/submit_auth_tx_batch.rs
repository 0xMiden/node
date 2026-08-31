use miden_node_block_producer::store::TransactionInputs;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::server::sequencer_api;
use miden_node_tracing::ErrorReport;
use miden_protocol::batch::ProposedBatch;
use tonic::Status;

use super::SequencerInternalService;

#[tonic::async_trait]
impl sequencer_api::SubmitAuthenticatedTxBatch for SequencerInternalService {
    type Input = (ProposedBatch, Vec<TransactionInputs>);
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::sequencer::AuthenticatedTransactionBatch,
    ) -> tonic::Result<Self::Input> {
        let proposed_batch = request
            .proposed_batch
            .ok_or_else(|| Status::invalid_argument("missing `proposed_batch` field"))?;
        let batch = miden_objects::conversion::decode_proposed_batch(
            proposed_batch,
            miden_protocol::MIN_PROOF_SECURITY_LEVEL,
        )
        .map_err(|err| Status::invalid_argument(format!("invalid proposed_batch: {err}")))?;

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
            .map_err(|err| {
                Status::invalid_argument(err.as_report_context("invalid auth_inputs"))
            })?;

        Ok((batch, inputs))
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn handle(
        &self,
        (batch, inputs): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        self.block_producer
            .submit_authenticated_tx_batch(batch, inputs)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
