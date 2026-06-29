use miden_node_block_producer::AuthenticatedTransaction;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::server::sequencer_api;
use miden_node_utils::ErrorReport;
use tonic::Status;

use super::PreAuthenticatedService;

#[tonic::async_trait]
impl sequencer_api::SubmitAuthenticatedTx for PreAuthenticatedService {
    type Input = AuthenticatedTransaction;
    type Output = proto::blockchain::BlockNumber;

    fn decode(request: proto::sequencer::AuthenticatedTransaction) -> tonic::Result<Self::Input> {
        AuthenticatedTransaction::try_from(request).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid authenticated transaction"))
        })
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn handle(&self, tx: Self::Input) -> tonic::Result<Self::Output> {
        self.block_producer
            .submit_authenticated_tx(tx)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
