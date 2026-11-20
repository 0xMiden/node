use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use miden_node_proto::domain::sign_block_request::BlockSigningInputs;
use miden_node_proto::errors::{ConversionError, ConversionResultExt};
use miden_node_proto::{DecodeExecution, DecodeMessage, generated as grpc};
use miden_node_tracing::{Instrument, info_span, instrument};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionHeader, TransactionId};
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, Word};
use miden_tx_batch::BatchVerifier;

use super::{StatusResultExt, ValidatorService};

/// Maximum time a proposal may lead the validator's clock to allow for operator clock skew.
const MAX_BLOCK_FUTURE_SKEW_SECS: u64 = 60;

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
            //
            // FIXME: Verify batch contents before signing. Validated transaction
            // IDs do not establish correct note aggregation or expiration. The current batch
            // kernel does not bind these fields, and transaction headers omit reference
            // blocks and expiration. Full validation needs more data or protocol support.
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
        BlockSigningInputs { proving_inputs, body, protocol_config }: Self::Input,
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
            .or_internal("sign_block semaphore closed")?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .or_internal("Validator clock is before the Unix epoch")?
            .as_secs();
        let header = &proving_inputs.block_header;
        let timestamp = header.timestamp();
        let latest_timestamp = now + MAX_BLOCK_FUTURE_SKEW_SECS;
        if u64::from(timestamp) > latest_timestamp {
            return Err(tonic::Status::invalid_argument(format!(
                "block timestamp {timestamp} is too far in the future (maximum {latest_timestamp})"
            )));
        }

        let protocol_config = self
            .resolve_protocol_config(header.protocol_config_commitment(), protocol_config)
            .await?;

        // Load the current chain tip from the database.
        let chain_tip = self
            .db
            .load_chain_tip()
            .await
            .or_internal("Failed to load chain tip")?
            .ok_or_else(|| tonic::Status::internal("Chain tip not found in database"))?;

        // Capture the tip height before the tip is consumed: a validated block at the same height
        // replaces the current tip rather than extending it. The semaphore held above guarantees
        // the tip cannot change in between.
        let chain_tip_num = chain_tip.block_num();

        // Validate the block against the current chain tip.
        let (signature, signed_block) = self
            .validate_block(header.clone(), body, chain_tip)
            .await
            .or_invalid_argument("Failed to validate block")?;

        // Capture the commitment that was signed before the block is moved into the persistence
        // closure, so it can be returned to the block producer for cross-checking.
        let block_commitment = signed_block.header().commitment();

        let block_transactions: Vec<TransactionId> = signed_block
            .body()
            .transactions()
            .iter()
            .flat_map(OrderedTransactionHeaders::as_slice)
            .map(TransactionHeader::id)
            .collect();

        // The signed block, proving inputs, and transaction positions are persisted atomically.
        //
        // A block at the current tip's height replaces that tip in the same transaction, so a crash
        // cannot leave transaction links from the replaced block behind.
        let new_block_num = signed_block.header().block_num().as_u32();
        let is_replacement = signed_block.header().block_num() == chain_tip_num;
        if is_replacement {
            self.db
                .replace_signed_block(
                    signed_block,
                    protocol_config,
                    block_transactions,
                    proving_inputs,
                )
                .await
        } else {
            self.db
                .insert_signed_block(
                    signed_block,
                    protocol_config,
                    block_transactions,
                    proving_inputs,
                )
                .await
        }
        .or_internal("Failed to persist signed block")?;

        // Publish the tip only after the block and its metadata have committed together.
        self.committed_tip.send_replace(BlockNumber::from(new_block_num));
        // A replacement stores no additional block. The count must stay equal to the number of
        // stored block headers, which is the value a restart reads.
        if !is_replacement {
            self.signed_blocks_count.fetch_add(1, Ordering::Relaxed);
        }

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
        let stored = self
            .db
            .load_protocol_config(commitment)
            .await
            .or_internal("Failed to load protocol config")?;

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
}
