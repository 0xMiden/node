use std::convert::Infallible;

use futures::TryFutureExt;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_node_proto::errors::MissingFieldHelper;
use miden_node_proto::generated::store::block_producer_server;
use miden_node_proto::generated::{self as proto};
use miden_node_proto::try_convert;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::Word;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockBody, BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::utils::Deserializable;
use tonic::{Request, Response, Status};
use tracing::Instrument;

use crate::errors::ApplyBlockError;
use crate::server::api::{
    StoreApi,
    conversion_error_to_status,
    read_account_id,
    read_account_ids,
    read_block_numbers,
    validate_note_commitments,
    validate_nullifiers,
};

// BLOCK PRODUCER ENDPOINTS
// ================================================================================================

#[tonic::async_trait]
impl block_producer_server::BlockProducer for StoreApi {
    /// Returns block header for the specified block number.
    ///
    /// If the block number is not provided, block header for the latest block is returned.
    async fn get_block_header_by_number(
        &self,
        request: Request<proto::rpc::BlockHeaderByNumberRequest>,
    ) -> Result<Response<proto::rpc::BlockHeaderByNumberResponse>, Status> {
        self.get_block_header_by_number_inner(request).await
    }

    /// Updates the local DB by inserting a new block header and the related data.
    async fn apply_block(
        &self,
        request: Request<proto::store::ApplyBlockRequest>,
    ) -> Result<Response<()>, Status> {
        let request = request.into_inner();
        // Read ordered batches.
        let ordered_batches =
            OrderedBatches::read_from_bytes(&request.ordered_batches).map_err(|err| {
                Status::invalid_argument(
                    err.as_report_context("failed to deserialize ordered batches"),
                )
            })?;
        // Read block.
        let block = request
            .block
            .ok_or(proto::store::ApplyBlockRequest::missing_field(stringify!(block)))?;
        // Read block header.
        let header: BlockHeader = block
            .header
            .ok_or(proto::blockchain::SignedBlock::missing_field(stringify!(header)))?
            .try_into()?;
        // Read block body.
        let body: BlockBody = block
            .body
            .ok_or(proto::blockchain::SignedBlock::missing_field(stringify!(body)))?
            .try_into()?;
        // Read signature.
        let signature: Signature = block
            .signature
            .ok_or(proto::blockchain::SignedBlock::missing_field(stringify!(signature)))?
            .try_into()?;

        // Get block inputs from ordered batches.
        let block_inputs =
            self.block_inputs_from_ordered_batches(&ordered_batches).await.map_err(|err| {
                Status::invalid_argument(
                    err.as_report_context("failed to get block inputs from ordered batches"),
                )
            })?;

        let span = tracing::Span::current();
        span.set_attribute("block.number", header.block_num());
        span.set_attribute("block.commitment", header.commitment());
        span.set_attribute("block.accounts.count", body.updated_accounts().len());
        span.set_attribute("block.output_notes.count", body.output_notes().count());
        span.set_attribute("block.nullifiers.count", body.created_nullifiers().len());

        // We perform the apply/prove block work in a separate task. This prevents the caller
        // cancelling the request and thereby cancelling the task at an arbitrary point of
        // execution.
        //
        // Normally this shouldn't be a problem, however our apply_block isn't quite ACID compliant
        // so things get a bit messy. This is more a temporary hack-around to minimize this risk.
        let this = self.clone();
        // TODO(sergerad): Use block proof.
        let _block_proof = tokio::spawn(
            async move {
                // SAFETY: The header, body, and signature are assumed to
                // correspond to each other because they are provided by the Block
                // Producer.
                let signed_block = SignedBlock::new_unchecked(header.clone(), body, signature);
                // Note: This is an internal endpoint, so its safe to expose the full error
                // report.
                this.state
                    .apply_block(signed_block)
                    .inspect_err(|err| {
                        span.set_error(err);
                    })
                    .map_err(|err| {
                        let code = match err {
                            ApplyBlockError::InvalidBlockError(_) => tonic::Code::InvalidArgument,
                            _ => tonic::Code::Internal,
                        };
                        Status::new(code, err.as_report())
                    })
                    .and_then(|_| {
                        this.block_prover
                            .prove(ordered_batches, block_inputs, &header)
                            .map_err(|err| Status::new(tonic::Code::Internal, err.as_report()))
                    })
                    .await
                    .map(Response::new)
            }
            .in_current_span(),
        )
        .await
        .map_err(|err| {
            tonic::Status::internal(err.as_report_context("joining apply_block task failed"))
        })
        .flatten()?;
        Ok(Response::new(()))
    }

    /// Returns data needed by the block producer to construct and prove the next block.
    async fn get_block_inputs(
        &self,
        request: Request<proto::store::BlockInputsRequest>,
    ) -> Result<Response<proto::store::BlockInputs>, Status> {
        let request = request.into_inner();

        let account_ids = read_account_ids::<Status>(&request.account_ids)?;
        let nullifiers = validate_nullifiers(&request.nullifiers)
            .map_err(|err| conversion_error_to_status(&err))?;
        let unauthenticated_note_commitments =
            validate_note_commitments(&request.unauthenticated_notes)?;
        let reference_blocks = read_block_numbers(&request.reference_blocks);
        let unauthenticated_note_commitments =
            unauthenticated_note_commitments.into_iter().collect();

        self.state
            .get_block_inputs(
                account_ids,
                nullifiers,
                unauthenticated_note_commitments,
                reference_blocks,
            )
            .await
            .map(proto::store::BlockInputs::from)
            .map(Response::new)
            .inspect_err(|err| tracing::Span::current().set_error(err))
            .map_err(|err| tonic::Status::internal(err.as_report()))
    }

    /// Fetches the inputs for a transaction batch from the database.
    ///
    /// See [`State::get_batch_inputs`] for details.
    async fn get_batch_inputs(
        &self,
        request: Request<proto::store::BatchInputsRequest>,
    ) -> Result<Response<proto::store::BatchInputs>, Status> {
        let request = request.into_inner();

        let note_commitments: Vec<Word> = try_convert(request.note_commitments)
            .collect::<Result<_, _>>()
            .map_err(|err| Status::invalid_argument(format!("Invalid note commitment: {err}")))?;

        let reference_blocks: Vec<u32> =
            try_convert::<_, Infallible, _, _>(request.reference_blocks)
                .collect::<Result<Vec<_>, _>>()
                .expect("operation should be infallible");
        let reference_blocks = reference_blocks.into_iter().map(BlockNumber::from).collect();

        self.state
            .get_batch_inputs(reference_blocks, note_commitments.into_iter().collect())
            .await
            .map(Into::into)
            .map(Response::new)
            .inspect_err(|err| tracing::Span::current().set_error(err))
            .map_err(|err| tonic::Status::internal(err.as_report()))
    }

    async fn get_transaction_inputs(
        &self,
        request: Request<proto::store::TransactionInputsRequest>,
    ) -> Result<Response<proto::store::TransactionInputs>, Status> {
        let request = request.into_inner();

        let account_id = read_account_id::<Status>(request.account_id)?;
        let nullifiers = validate_nullifiers(&request.nullifiers)
            .map_err(|err| conversion_error_to_status(&err))?;
        let unauthenticated_note_commitments =
            validate_note_commitments(&request.unauthenticated_notes)?;

        let tx_inputs = self
            .state
            .get_transaction_inputs(account_id, &nullifiers, unauthenticated_note_commitments)
            .await
            .inspect_err(|err| tracing::Span::current().set_error(err))
            .map_err(|err| tonic::Status::internal(err.as_report()))?;

        let block_height = self.state.latest_block_num().await.as_u32();

        Ok(Response::new(proto::store::TransactionInputs {
            account_state: Some(proto::store::transaction_inputs::AccountTransactionInputRecord {
                account_id: Some(account_id.into()),
                account_commitment: Some(tx_inputs.account_commitment.into()),
            }),
            nullifiers: tx_inputs
                .nullifiers
                .into_iter()
                .map(|nullifier| {
                    proto::store::transaction_inputs::NullifierTransactionInputRecord {
                        nullifier: Some(nullifier.nullifier.into()),
                        block_num: nullifier.block_num.as_u32(),
                    }
                })
                .collect(),
            found_unauthenticated_notes: tx_inputs
                .found_unauthenticated_notes
                .into_iter()
                .map(Into::into)
                .collect(),
            new_account_id_prefix_is_unique: tx_inputs.new_account_id_prefix_is_unique,
            block_height,
        }))
    }
}
