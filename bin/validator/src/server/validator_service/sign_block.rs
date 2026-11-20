use std::sync::Arc;

use miden_node_db::DatabaseError;
use miden_node_proto::domain::sign_block_request::BlockSigningInputs;
use miden_node_proto::errors::{ConversionError, ConversionResultExt};
use miden_node_proto::{DecodeExecution, DecodeMessage, generated as grpc};
use miden_node_tracing::{Instrument, info_span, instrument};
use miden_protocol::block::{BlockHeader, BlockSignatures, SignedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, Word};
use miden_tx_batch::BatchVerifier;

use super::{StatusResultExt, ValidatorError, ValidatorService};

#[tonic::async_trait]
impl grpc::server::miden_validator_v1_validator_service::SignBlock for ValidatorService {
    const DECODE_EXECUTION: DecodeExecution = DecodeExecution::Blocking;

    type Input = BlockSigningInputs;
    type Output = (Signature, Word, PublicKey);

    #[instrument(err)]
    fn decode(request: grpc::miden::validator::v1::SignBlockRequest) -> tonic::Result<Self::Input> {
        let inputs = request
            .decode_fields()
            .context("failed to decode")
            .map_err(ConversionError::into_status)?
            // SAFETY: Construction checks local batch invariants and block witnesses.
            // validate_block checks transaction IDs and the trusted parent before signing.
            .build_with_body_unchecked()
            .context("failed to build unchecked")
            .map_err(ConversionError::into_status)?;

        let verifier = BatchVerifier::new(MIN_PROOF_SECURITY_LEVEL);
        for batch in inputs.proving_inputs.tx_batches.as_slice() {
            verifier.verify(batch).or_invalid_argument("invalid batch proof")?;
        }
        Ok(inputs)
    }

    #[instrument(err)]
    fn encode(
        output: Self::Output,
    ) -> tonic::Result<grpc::miden::validator::v1::SignBlockResponse> {
        let (signature, block_commitment, public_key) = output;
        Ok(grpc::miden::validator::v1::SignBlockResponse {
            signature: Some(signature.into()),
            block_commitment: Some(block_commitment.into()),
            public_key: Some((&public_key).into()),
        })
    }

    async fn handle(
        &self,
        BlockSigningInputs {
            proving_inputs,
            body,
            protocol_config: supplied_config,
        }: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        // Reject requests while a backup subscription is streaming.
        let _guard = self.serve_lock.try_read().map_err(|_| {
            tonic::Status::resource_exhausted("validator is busy streaming a backup")
        })?;

        let signing_guard = Arc::clone(&self.signing_lock)
            .lock_owned()
            .instrument(info_span!("acquire_signing_lock"))
            .await;

        let header = &proving_inputs.block_header;
        let changes_validator_config = self
            .validate_block(header, &body)
            .await
            .map_err(ValidatorError::into_validation_status)?;

        let parent = proving_inputs.block_inputs.prev_block_header();
        let protocol_config =
            if header.protocol_config_commitment() == parent.protocol_config_commitment() {
                None
            } else {
                Some(supplied_config.ok_or_else(|| {
                    tonic::Status::invalid_argument(
                        "protocol_config is required when the active configuration changes",
                    )
                })?)
            };

        // Reconstruction checked the witnesses against the supplied parent, and decode verified
        // each batch proof. Local checks established the parent, transaction IDs, and signing key.
        //
        // FIXME: Correct note aggregation and batch expiration remain unverified by the batch kernel.
        let signature = self.sign_header(header).await.or_internal("Failed to sign block")?;
        let block_commitment = header.commitment();

        // The backup contains this validator's signature. The producer assembles the full set.
        let own_signature = BlockSignatures::new(vec![signature.clone()])
            .expect("a single signature is within the signature set bounds");
        let signed_block = SignedBlock::new_unchecked(header.clone(), body, own_signature);

        let _guard_until_commit = self
            .db
            .write("upsert_signed_block", move |tx| {
                tx.upsert_signed_block(&signed_block, protocol_config.as_ref(), &proving_inputs)?;
                if changes_validator_config {
                    tx.delete_pending_validator_config()?;
                }
                // SQLite can finish the write after the RPC is cancelled. Returning the guard keeps
                // the signing lock held through commit in that case too.
                Ok::<_, DatabaseError>(signing_guard)
            })
            .instrument(info_span!("upsert_signed_block"))
            .await
            .or_internal("Failed to persist signed block")?;

        Ok((signature, block_commitment, self.signer.public_key()))
    }
}

impl ValidatorService {
    /// Signs a block header using the validator's signer.
    #[instrument(
        name = "sign_block",
        err,
        fields(
            block.number = header.block_num(),
        ),
    )]
    async fn sign_header(&self, header: &BlockHeader) -> Result<Signature, ValidatorError> {
        self.signer
            .sign_commitment(header.commitment())
            .await
            .map_err(|err| ValidatorError::BlockSigningFailed(err.to_string()))
    }
}
