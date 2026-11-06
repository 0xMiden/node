use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{instrument_v2, miden_span_record};
use miden_protocol::block::{BlockHeader, BlockSignatures, ProposedBlock, SignedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::transaction::TransactionHeader;

use super::{ValidatorError, ValidatorService};

impl ValidatorService {
    /// Validates a proposed block by checking:
    /// 1. All transactions have been previously validated by this validator.
    /// 2. The block header can be successfully built from the proposed block.
    /// 3. The block is either: a. The valid next block in the chain (sequential block number, matching
    ///    previous block commitment), or b. A replacement block at the same height as the current chain
    ///    tip, validated against the previous block header.
    ///
    /// On success, returns the signature and validated signed block for persistence.
    #[instrument_v2(err)]
    pub async fn validate_block(
        &self,
        proposed_block: ProposedBlock,
        chain_tip: BlockHeader,
    ) -> Result<(Signature, SignedBlock), ValidatorError> {
        miden_span_record!(tip.number = chain_tip.block_num());

        // Search for any proposed transactions that have not previously been validated.
        let proposed_tx_ids =
            proposed_block.transactions().map(TransactionHeader::id).collect::<Vec<_>>();
        let unvalidated_txs = self
            .db
            .find_unvalidated_transactions(proposed_tx_ids)
            .await
            .map_err(ValidatorError::DatabaseError)?;

        // All proposed transactions must have been validated.
        if !unvalidated_txs.is_empty() {
            return Err(ValidatorError::UnvalidatedTransactions(unvalidated_txs));
        }
        // Build the block header. This computes the account, nullifier and note tree roots plus the
        // chain and transaction commitments — hashing proportional to block contents — so it runs
        // on a blocking thread rather than pinning an async worker.
        let (proposed_header, proposed_body) =
            spawn_blocking_in_current_span(move || proposed_block.into_header_and_body())
                .await
                .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
                .map_err(ValidatorError::BlockBuildingFailed)?;

        miden_span_record!(
            block.number = proposed_header.block_num(),
            block.commitment = proposed_header.commitment()
        );

        // If the proposed block has the same block number as the current chain tip, this is a
        // replacement block. Validate it against the previous block header.
        let prev = if proposed_header.block_num() == chain_tip.block_num() {
            // The genesis block cannot be replaced (genesis block has no parent).
            let prev_block_num =
                chain_tip.block_num().parent().ok_or(ValidatorError::NoPrevBlockHeader)?;
            self.db
                .load_block_header(prev_block_num)
                .await
                .map_err(ValidatorError::DatabaseError)?
                .ok_or(ValidatorError::NoPrevBlockHeader)?
        } else {
            // Proposed block is a new block. Block number must be sequential.
            let expected_block_num = chain_tip.block_num().child();
            if proposed_header.block_num() != expected_block_num {
                return Err(ValidatorError::BlockNumberMismatch {
                    expected: expected_block_num,
                    actual: proposed_header.block_num(),
                });
            }
            // Current chain tip is the parent of the proposed block.
            chain_tip
        };

        // The proposed block's parent must match the block that the Validator has determined is its
        // parent (either chain tip or parent of chain tip).
        if proposed_header.prev_block_commitment() != prev.commitment() {
            return Err(ValidatorError::PrevBlockCommitmentMismatch);
        }

        // Check that our key is a member of the validator set authorized to sign this block,
        // which is the set committed to by the parent's header.
        //
        // Otherwise we would be producing a signature that cannot be placed in the block's
        // signature set.
        let signing_key = self.signer.public_key();
        if !prev.validator_config().keys().contains(&signing_key) {
            return Err(ValidatorError::ValidatorKeyNotInSet { actual: signing_key });
        }

        let signature = self.sign_header(&proposed_header).await?;

        // Prepare the signed block for persistence.
        //
        // Note that the backup only carries this validator's own signature: the complete,
        // positionally ordered signature set exists only at the block producer once it has
        // aggregated the responses of all validators. Consumers of the backup stream must not
        // expect to verify the full signature set from these blocks.
        let own_signature = BlockSignatures::new(vec![signature.clone()])
            .expect("a single signature is within the signature set bounds");
        let signed_block =
            SignedBlock::new_unchecked(proposed_header, proposed_body, own_signature);
        Ok((signature, signed_block))
    }

    /// Signs a block header using the validator's signer.
    #[instrument_v2(
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
