use miden_node_proto::domain::sequencer::TransactionInputs;
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::server::miden_sequencer_v1_sequencer_service;
use miden_node_proto::{DecodeExecution, DecodeMessage, VerifyWith, generated as proto};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};

use super::SequencerInternalService;

#[tonic::async_trait]
impl miden_sequencer_v1_sequencer_service::SubmitAuthenticatedTxBatch for SequencerInternalService {
    const DECODE_EXECUTION: DecodeExecution = DecodeExecution::Blocking;

    type Input = (ProvenBatch, ProposedBatch, Vec<TransactionInputs>);
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::miden::sequencer::v1::SubmitAuthenticatedTxBatchRequest,
    ) -> tonic::Result<Self::Input> {
        request
            .decode_fields()
            .and_then(|request| request.batch.verify_with(MIN_PROOF_SECURITY_LEVEL))
            .map_err(ConversionError::into_status)
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
        (proof, batch, inputs): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
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
