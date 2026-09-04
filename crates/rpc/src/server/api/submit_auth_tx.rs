use miden_node_block_producer::AuthenticatedTransaction;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::server::sequencer_api;
use miden_node_tracing::ErrorReport;
use tonic::Status;

use super::{
    SequencerInternalService,
    ensure_transactions_have_fee_notes,
    get_block_header_error_to_status,
};

#[tonic::async_trait]
impl sequencer_api::SubmitAuthenticatedTx for SequencerInternalService {
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

    async fn handle(
        &self,
        tx: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let (block_num, commitment) = tx.reference_block();
        let reference_header = self
            .state
            .view()
            .get_block_header(Some(block_num), false)
            .await
            .map_err(get_block_header_error_to_status)?
            .0
            .ok_or_else(|| Status::invalid_argument(format!("unknown block {block_num}")))?;

        if reference_header.commitment() != commitment {
            return Err(Status::invalid_argument(format!(
                "reference block's commitment {commitment} at block {block_num} does not match the chain's commitment of {}",
                reference_header.commitment(),
            )));
        }

        ensure_transactions_have_fee_notes([tx.raw_proven_transaction()])?;

        self.block_producer
            .submit_authenticated_tx(tx)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
