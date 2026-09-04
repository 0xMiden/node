use std::sync::atomic::Ordering;

use miden_node_proto::generated as grpc;
use miden_node_tracing::{Instrument, info_span, miden_instrument};
use miden_protocol::Word;
use miden_protocol::block::{BlockNumber, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use miden_tx::utils::serde::{Deserializable, Serializable};

use super::{StatusResultExt, ValidatorService};
use crate::COMPONENT;

#[tonic::async_trait]
impl grpc::server::validator_api::SignBlock for ValidatorService {
    type Input = ProposedBlock;
    type Output = (Signature, Word, PublicKey);

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    fn decode(request: grpc::blockchain::ProposedBlock) -> tonic::Result<Self::Input> {
        ProposedBlock::read_from_bytes(&request.proposed_block)
            .or_invalid_argument("Failed to deserialize proposed block")
    }

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    fn encode(output: Self::Output) -> tonic::Result<grpc::blockchain::SignBlockResponse> {
        let (signature, block_commitment, public_key) = output;
        Ok(grpc::blockchain::SignBlockResponse {
            signature: Some(grpc::blockchain::BlockSignature { signature: signature.to_bytes() }),
            block_commitment: Some(block_commitment.into()),
            public_key: Some((&public_key).into()),
        })
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
            .or_internal("sign_block semaphore closed")?;

        // Load the current chain tip from the database.
        let chain_tip = self
            .db
            .load_chain_tip()
            .await
            .or_internal("Failed to load chain tip")?
            .ok_or_else(|| tonic::Status::internal("Chain tip not found in database"))?;

        // Capture the block's transactions in block order before the proposed block is consumed, so
        // their positions can be persisted alongside the signed header.
        let block_transactions: Vec<TransactionId> =
            proposed_block.transactions().map(TransactionHeader::id).collect();
        // Capture the tip height before the tip is consumed: a validated block at the same height
        // replaces the current tip rather than extending it. The semaphore held above guarantees
        // the tip cannot change in between.
        let chain_tip_num = chain_tip.block_num();

        // Validate the block against the current chain tip.
        let (signature, header) = self
            .validate_block(proposed_block, chain_tip)
            .await
            .or_invalid_argument("Failed to validate block")?;

        // Capture the commitment that was signed before `header` is moved into the persistence
        // closure, so it can be returned to the block producer for cross-checking.
        let block_commitment = header.commitment();

        // Persist the signed header together with the block position of each of its transactions. A
        // validated block at the tip's height replaces the current tip, which also deletes the
        // replaced block — atomically with persisting its successor, so a crash cannot leave the
        // replaced block's links behind.
        let new_block_num = header.block_num().as_u32();
        if header.block_num() == chain_tip_num {
            self.db
                .replace_signed_block(header, block_transactions)
                .await
                .or_internal("Failed to replace signed block")?;
        } else {
            self.db
                .insert_signed_block(header, block_transactions)
                .await
                .or_internal("Failed to insert signed block")?;
        }

        // Update the in-memory counters after successful persistence. The block has already been
        // backed up to the block store by `validate_block`, so it is available to subscribers by
        // the time they observe this new tip.
        self.committed_tip.send_replace(BlockNumber::from(new_block_num));
        self.signed_blocks_count.fetch_add(1, Ordering::Relaxed);

        Ok((signature, block_commitment, self.signer.public_key()))
    }
}
