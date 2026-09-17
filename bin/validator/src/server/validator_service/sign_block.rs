use std::sync::atomic::Ordering;

use miden_node_proto::{DecodeMessageExt, generated as grpc};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{ErrorReport, Instrument, info_span, miden_instrument};
use miden_protocol::Word;
use miden_protocol::block::{BlockHeader, BlockNumber, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::protocol_config::ProtocolConfig;

use super::ValidatorService;
use crate::COMPONENT;

#[tonic::async_trait]
impl grpc::server::validator_api::SignBlock for ValidatorService {
    type Input = grpc::validator::SignBlockRequest;
    type Output = (Signature, Word, PublicKey);

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    fn decode(request: grpc::validator::SignBlockRequest) -> tonic::Result<Self::Input> {
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

        let (proposed_block, protocol_config, protocol_config_commitment) =
            spawn_blocking_in_current_span(move || {
                let request = request
                    // SAFETY: Construction checks local batch invariants and block witnesses.
                    // validate_block checks transaction IDs and the trusted parent before signing.
                    //
                    // FIXME: Verify batch proofs and contents before signing. Validated transaction
                    // IDs do not establish correct note aggregation or expiration. The current batch
                    // kernel does not bind these fields, and transaction headers omit reference
                    // blocks and expiration. Full validation needs more data or protocol support.
                    .decode_and_build_unchecked()
                    .map_err(miden_node_proto::errors::conversion_error_to_status)?;
                let protocol_config = request.protocol_config;
                let protocol_config_commitment = request.block_header.protocol_config_commitment();
                let proposed_block = ProposedBlock::new_at(
                    request.block_inputs,
                    request.tx_batches.into_vec(),
                    request.block_header.timestamp(),
                )
                .map(|block| {
                    block
                        .with_next_validator_config(request.block_header.validator_config().clone())
                        .with_next_protocol_config(
                            request.block_header.next_protocol_config().cloned(),
                        )
                })
                .map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                Ok::<_, tonic::Status>((
                    proposed_block,
                    protocol_config,
                    protocol_config_commitment,
                ))
            })
            .await
            .map_err(|error| {
                tonic::Status::internal(format!("block decoding task failed: {error}"))
            })??;
        let protocol_config = self
            .resolve_protocol_config(protocol_config_commitment, protocol_config)
            .await?;

        let block_num = proposed_block.block_num();
        let previous_backup = self.block_store.load_block(block_num).await.map_err(|err| {
            tonic::Status::internal(format!("Failed to load previous block backup: {err}"))
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

        // Persist the signed header.
        let new_block_num = header.block_num().as_u32();
        self.persist_signed_header(header, protocol_config, previous_backup).await?;

        // Update the in-memory counters after successful persistence. The block has already been
        // backed up to the block store by `validate_block`, so it is available to subscribers by
        // the time they observe this new tip.
        self.committed_tip.send_replace(BlockNumber::from(new_block_num));
        self.signed_blocks_count.fetch_add(1, Ordering::Relaxed);

        Ok((signature, block_commitment, self.signer.public_key()))
    }
}

impl ValidatorService {
    /// Resolves and validates the active configuration before the block is signed.
    async fn resolve_protocol_config(
        &self,
        commitment: Word,
        supplied: Option<ProtocolConfig>,
    ) -> tonic::Result<ProtocolConfig> {
        let stored = self.db.load_protocol_config(commitment).await.map_err(|err| {
            tonic::Status::internal(format!("Failed to load protocol config: {}", err.as_report()))
        })?;

        match (supplied, stored) {
            (Some(supplied), Some(stored)) if supplied != stored => Err(tonic::Status::internal(
                format!("Stored protocol config {commitment} differs from the supplied config"),
            )),
            (Some(supplied), _) => Ok(supplied),
            (None, Some(stored)) => Ok(stored),
            (None, None) => Err(tonic::Status::invalid_argument(format!(
                "Protocol config {commitment} is not stored"
            ))),
        }
    }

    /// Persists the signed header and restores an existing backup if persistence fails.
    async fn persist_signed_header(
        &self,
        header: BlockHeader,
        protocol_config: ProtocolConfig,
        previous_backup: Option<Vec<u8>>,
    ) -> tonic::Result<()> {
        let block_num = header.block_num();
        let Err(err) = self
            .db
            .upsert_block_header_with_protocol_config(header, Some(protocol_config))
            .await
        else {
            return Ok(());
        };

        if let Some(previous_backup) = previous_backup {
            self.block_store
                .save_block(block_num, &previous_backup)
                .await
                .map_err(|restore_err| {
                    tonic::Status::internal(format!(
                        "Failed to persist block header: {}; failed to restore block backup: {restore_err}",
                        err.as_report()
                    ))
                })?;
        }
        Err(tonic::Status::internal(format!(
            "Failed to persist block header: {}",
            err.as_report()
        )))
    }
}
