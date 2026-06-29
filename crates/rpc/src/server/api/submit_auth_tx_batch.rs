use miden_node_block_producer::store::TransactionInputs;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::server::sequencer_api;
use miden_node_utils::ErrorReport;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::utils::serde::Deserializable;
use tonic::Status;

use super::PreAuthenticatedService;

#[tonic::async_trait]
impl sequencer_api::SubmitAuthenticatedTxBatch for PreAuthenticatedService {
    type Input = (ProposedBatch, Vec<TransactionInputs>);
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::sequencer::AuthenticatedTransactionBatch,
    ) -> tonic::Result<Self::Input> {
        let batch = ProposedBatch::read_from_bytes(&request.proposed_batch).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid proposed_batch"))
        })?;
        let inputs = request
            .auth_inputs
            .into_iter()
            .map(TransactionInputs::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                Status::invalid_argument(err.as_report_context("invalid auth_inputs"))
            })?;

        if batch.transactions().len() != inputs.len() {
            return Err(Status::invalid_argument(format!(
                "Number of inputs {} does not match number of transactions {} in batch",
                inputs.len(),
                batch.transactions().len()
            )));
        }

        Ok((batch, inputs))
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn handle(&self, (batch, inputs): Self::Input) -> tonic::Result<Self::Output> {
        self.block_producer
            .submit_authenticated_tx_batch(batch, inputs)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
