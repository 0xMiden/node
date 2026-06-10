use std::sync::atomic::Ordering;

use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::block::ProposedBlock;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_tx::utils::serde::{Deserializable, Serializable};

use crate::db::{load_chain_tip, upsert_block_header};
use crate::server::ValidatorServer;

#[tonic::async_trait]
impl grpc::server::validator_api::SignBlock for ValidatorServer {
    type Input = ProposedBlock;
    type Output = (Signature, Word);

    fn decode(request: grpc::blockchain::ProposedBlock) -> tonic::Result<Self::Input> {
        ProposedBlock::read_from_bytes(&request.proposed_block).map_err(|err| {
            tonic::Status::invalid_argument(
                err.as_report_context("Failed to deserialize proposed block"),
            )
        })
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::blockchain::SignBlockResponse> {
        let (signature, block_commitment) = output;
        Ok(grpc::blockchain::SignBlockResponse {
            signature: Some(grpc::blockchain::BlockSignature { signature: signature.to_bytes() }),
            block_commitment: Some(block_commitment.into()),
        })
    }

    async fn handle(&self, proposed_block: Self::Input) -> tonic::Result<Self::Output> {
        // Serialize sign_block requests to prevent race conditions between loading the chain tip
        // and persisting the validated block header.
        let _permit = self.sign_block_semaphore.acquire().await.map_err(|err| {
            tonic::Status::internal(format!("sign_block semaphore closed: {err}"))
        })?;

        // Load the current chain tip from the database.
        let chain_tip = self
            .db
            .query("load_chain_tip", load_chain_tip)
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

        // Persist the validated block header.
        let new_block_num = header.block_num().as_u32();
        self.db
            .transact("upsert_block_header", move |conn| upsert_block_header(conn, &header))
            .await
            .map_err(|err| {
                tonic::Status::internal(format!(
                    "Failed to persist block header: {}",
                    err.as_report()
                ))
            })?;

        // Update the in-memory counters after successful persistence.
        self.chain_tip.store(new_block_num, Ordering::Relaxed);
        self.signed_blocks_count.fetch_add(1, Ordering::Relaxed);

        Ok((signature, block_commitment))
    }
}
