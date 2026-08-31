use std::sync::atomic::Ordering;

use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_node_proto::generated as grpc;
use miden_node_tracing::{ErrorReport, Instrument, info_span, miden_instrument};
use miden_protocol::block::{BlockNumber, ProposedBlock, SignedBlock};

use super::ValidatorService;
use crate::COMPONENT;

#[tonic::async_trait]
impl grpc::server::validator_api::SignBlock for ValidatorService {
    type Input = ProposedBlock;
    type Output = SignedBlock;

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    fn decode(request: grpc::block_proving::BlockProofRequest) -> tonic::Result<Self::Input> {
        let request = BlockProofRequest::try_from(request).map_err(|err| {
            tonic::Status::invalid_argument(
                err.as_report_context("Failed to decode proposed block inputs"),
            )
        })?;
        let header = request.block_header;

        ProposedBlock::new_at(
            request.block_inputs,
            request.tx_batches.into_vec(),
            header.timestamp(),
        )
        .map_err(|err| {
            tonic::Status::invalid_argument(err.as_report_context("Failed to build proposed block"))
        })
        .map(|block| {
            block
                .with_next_validator_config(header.validator_config().clone())
                .with_next_protocol_config(header.next_protocol_config().cloned())
        })
    }

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    fn encode(output: Self::Output) -> tonic::Result<grpc::blockchain::SignedBlock> {
        Ok(output.into())
    }

    async fn handle(
        &self,
        proposed_block: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        // Reject requests while a backup subscription is streaming.
        let _guard = self.serve_lock.try_read().map_err(|_| {
            tonic::Status::resource_exhausted("validator is busy streaming a backup")
        })?;

        // Serialize sign_block requests to prevent race conditions between loading the chain tip
        // and persisting the validated block header.
        let _permit = self
            .sign_block_semaphore
            .acquire()
            .instrument(info_span!("acquire_permit"))
            .await
            .map_err(|err| {
                tonic::Status::internal(format!("sign_block semaphore closed: {err}"))
            })?;

        // Load the current chain tip from the database.
        let chain_tip = self
            .db
            .load_chain_tip()
            .await
            .map_err(|err| {
                tonic::Status::internal(format!("Failed to load chain tip: {}", err.as_report()))
            })?
            .ok_or_else(|| tonic::Status::internal("Chain tip not found in database"))?;

        // Validate the block against the current chain tip.
        let signed_block = self.validate_block(proposed_block, chain_tip).await.map_err(|err| {
            tonic::Status::invalid_argument(format!(
                "Failed to validate block: {}",
                err.as_report()
            ))
        })?;
        let header = signed_block.header().clone();

        // Persist the signed header.
        let new_block_num = header.block_num().as_u32();
        self.db.upsert_block_header(header).await.map_err(|err| {
            tonic::Status::internal(format!("Failed to persist block header: {}", err.as_report()))
        })?;

        // Update the in-memory counters after successful persistence. The block has already been
        // backed up to the block store by `validate_block`, so it is available to subscribers by
        // the time they observe this new tip.
        self.committed_tip.send_replace(BlockNumber::from(new_block_num));
        self.signed_blocks_count.fetch_add(1, Ordering::Relaxed);

        Ok(signed_block)
    }
}
