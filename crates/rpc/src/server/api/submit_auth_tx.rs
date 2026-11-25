use miden_node_block_producer::ensure_transaction_has_fee;
use miden_node_proto::domain::sequencer::TransactionCandidate;
use miden_node_proto::generated::server::miden_sequencer_v1_sequencer_service;
use miden_node_proto::{DecodeExecution, DecodeMessageExt, generated as proto};
use miden_node_tracing::ErrorReport;
use tonic::Status;

use super::{SequencerInternalService, database_error_to_status, require_protocol_config};

#[tonic::async_trait]
impl miden_sequencer_v1_sequencer_service::SubmitAuthenticatedTx for SequencerInternalService {
    const DECODE_EXECUTION: DecodeExecution = DecodeExecution::Blocking;

    type Input = TransactionCandidate;
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::miden::sequencer::v1::SubmitAuthenticatedTxRequest,
    ) -> tonic::Result<Self::Input> {
        let request = request
            .transaction
            .ok_or_else(|| tonic::Status::invalid_argument("missing transaction"))?;
        request
            // SAFETY: Network isolation must restrict this endpoint to trusted full nodes. The
            // sender supplies proof and store validation. The handler checks the reference block
            // locally, and the mempool checks conflicts, dependencies, and expiration.
            .decode_and_build_unchecked()
            .map_err(|err| {
                Status::invalid_argument(err.as_report_context("invalid authenticated transaction"))
            })
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<proto::miden::sequencer::v1::SubmitAuthenticatedTxResponse> {
        Ok(proto::miden::sequencer::v1::SubmitAuthenticatedTxResponse {
            block_num: output.block_num,
        })
    }

    async fn handle(
        &self,
        tx: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        self.account_admission
            .check(tx.raw_proven_transaction().account_update())
            .await?;

        let (block_num, commitment) = tx.reference_block();
        let (reference_header, protocol_config) = self
            .state
            .read(move |view| {
                let Some(header) = view.tx.select_block_header(block_num)? else {
                    return Ok(None);
                };
                let config =
                    require_protocol_config(&view.tx, header.protocol_config_commitment())?;
                Ok(Some((header, config)))
            })
            .await
            .map_err(|err| database_error_to_status(&err))?
            .ok_or_else(|| Status::invalid_argument(format!("unknown block {block_num}")))?;

        if reference_header.commitment() != commitment {
            return Err(Status::invalid_argument(format!(
                "reference block's commitment {commitment} at block {block_num} does not match the chain's commitment of {}",
                reference_header.commitment(),
            )));
        }

        ensure_transaction_has_fee(
            tx.raw_proven_transaction(),
            protocol_config.fee_asset_id(),
            reference_header.fee_parameters(),
        )
        .map_err(Status::from)?;

        self.block_producer
            .submit_authenticated_tx(tx)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
