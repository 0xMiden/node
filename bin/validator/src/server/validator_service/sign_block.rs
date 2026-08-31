use std::sync::atomic::Ordering;

use miden_node_proto::{BlockProofRequest, generated as grpc};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{ErrorReport, Instrument, info_span, miden_instrument};
use miden_protocol::Word;
use miden_protocol::block::{BlockNumber, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::transaction::{TransactionHeader, TransactionId};

use super::ValidatorService;
use crate::COMPONENT;

#[tonic::async_trait]
impl grpc::server::validator_api::SignBlock for ValidatorService {
    type Input = grpc::block_proving::BlockProofRequest;
    type Output = (Signature, Word, PublicKey);

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    fn decode(request: grpc::block_proving::BlockProofRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    fn encode(output: Self::Output) -> tonic::Result<grpc::validator::SignBlockResponse> {
        let (signature, block_commitment, public_key) = output;
        Ok(grpc::validator::SignBlockResponse {
            signature: Some(signature.into()),
            block_commitment: Some(block_commitment.into()),
            public_key: Some((&public_key).into()),
        })
    }

    async fn handle(
        &self,
        request: Self::Input,
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

        let proposed_block = spawn_blocking_in_current_span(move || {
            let request = BlockProofRequest::try_from(request).map_err(tonic::Status::from)?;
            ProposedBlock::new_at(
                request.block_inputs,
                request.tx_batches.into_vec(),
                request.block_header.timestamp(),
            )
            .map(|block| {
                block
                    .with_next_validator_config(request.block_header.validator_config().clone())
                    .with_next_protocol_config(request.block_header.next_protocol_config().cloned())
            })
            .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
        })
        .await
        .map_err(|error| {
            tonic::Status::internal(format!("block decoding task failed: {error}"))
        })??;

        // Load the current chain tip from the database.
        let chain_tip = self
            .db
            .load_chain_tip()
            .await
            .map_err(|err| {
                tonic::Status::internal(format!("Failed to load chain tip: {}", err.as_report()))
            })?
            .ok_or_else(|| tonic::Status::internal("Chain tip not found in database"))?;

        // Capture the block's transactions in block order before the proposed block is consumed, so
        // their positions can be persisted alongside the signed header.
        let block_transactions: Vec<TransactionId> =
            proposed_block.transactions().map(TransactionHeader::id).collect();

        // Validate the block against the current chain tip.
        let (signature, header) =
            self.validate_block(proposed_block, chain_tip).await.map_err(|err| {
                tonic::Status::invalid_argument(format!(
                    "Failed to validate block: {}",
                    err.as_report()
                ))
            })?;

        // Capture the commitment that was signed before `header` is moved into the persistence
        // closure, so it can be returned to the block producer for cross-checking.
        let block_commitment = header.commitment();

        // Persist the signed header together with the block position of each of its transactions.
        let new_block_num = header.block_num().as_u32();
        self.db.upsert_signed_block(header, block_transactions).await.map_err(|err| {
            tonic::Status::internal(format!("Failed to persist block header: {}", err.as_report()))
        })?;

        // Update the in-memory counters after successful persistence. The block has already been
        // backed up to the block store by `validate_block`, so it is available to subscribers by
        // the time they observe this new tip.
        self.committed_tip.send_replace(BlockNumber::from(new_block_num));
        self.signed_blocks_count.fetch_add(1, Ordering::Relaxed);

        Ok((signature, block_commitment, self.signer.public_key()))
    }
}
