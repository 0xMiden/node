use miden_node_proto::generated::server::miden_sequencer_v1_sequencer_service;
use miden_node_proto::{DecodeMessageExt, generated as proto};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use tonic::Status;

use super::SequencerInternalService;

#[tonic::async_trait]
impl miden_sequencer_v1_sequencer_service::SubmitAuthenticatedTxBatch for SequencerInternalService {
    type Input = proto::miden::sequencer::v1::AuthenticatedTransactionBatch;
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::miden::sequencer::v1::SubmitAuthenticatedTxBatchRequest,
    ) -> tonic::Result<Self::Input> {
        request.batch.ok_or_else(|| tonic::Status::invalid_argument("missing batch"))
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<proto::miden::sequencer::v1::SubmitAuthenticatedTxBatchResponse> {
        Ok(proto::miden::sequencer::v1::SubmitAuthenticatedTxBatchResponse {
            block_num: output.block_num,
        })
    }

    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let (proof, batch, inputs) = spawn_blocking_in_current_span(move || {
            request
                .decode_and_verify_with(miden_protocol::MIN_PROOF_SECURITY_LEVEL)
                .map_err(miden_node_proto::errors::ConversionError::into_status)
        })
        .await
        .map_err(|err| {
            Status::internal(format!("authenticated batch decoding task failed: {err}"))
        })??;

        for tx in batch.transactions() {
            self.account_admission.check(tx.account_update()).await?;
        }

        self.block_producer
            .submit_authenticated_tx_batch(proof, batch, inputs)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
