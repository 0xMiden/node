use miden_node_proto::generated::server::sequencer_api;
use miden_node_proto::{DecodeMessageExt, generated as proto};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
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
        let (batch, inputs) = spawn_blocking_in_current_span(move || {
            request
                .decode_and_verify_with(miden_protocol::MIN_PROOF_SECURITY_LEVEL)
                .map_err(miden_node_proto::errors::conversion_error_to_status)
        })
        .await
        .map_err(|err| {
            Status::internal(format!("authenticated batch decoding task failed: {err}"))
        })??;

        for tx in batch.transactions() {
            self.account_admission.check(tx.account_update()).await?;
        }

        ensure_transactions_have_fee_notes(batch.transactions().iter().map(AsRef::as_ref))?;

        self.block_producer
            .submit_authenticated_tx_batch(batch, inputs)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
