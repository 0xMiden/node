use miden_node_tracing::{instrument, miden_span_record};
use miden_protocol::block::{BlockBody, BlockHeader};
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionHeader};

use super::{ValidatorError, ValidatorService};

impl ValidatorService {
    /// Checks that the validator recognizes the transactions, accepts the parent for this height,
    /// and holds a key authorized by that parent.
    #[instrument(err)]
    pub(super) async fn validate_block(
        &self,
        proposed_header: &BlockHeader,
        proposed_body: &BlockBody,
        chain_tip: BlockHeader,
    ) -> Result<(), ValidatorError> {
        miden_span_record!(tip.number = chain_tip.block_num());

        // Search for any proposed transactions that have not previously been validated.
        let proposed_tx_ids = proposed_body
            .transactions()
            .iter()
            .flat_map(OrderedTransactionHeaders::as_slice)
            .map(TransactionHeader::id)
            .collect::<Vec<_>>();
        let unvalidated_txs = self
            .db
            .find_unvalidated_transactions(proposed_tx_ids)
            .await
            .map_err(ValidatorError::DatabaseError)?;

        // All proposed transactions must have been validated.
        if !unvalidated_txs.is_empty() {
            return Err(ValidatorError::UnvalidatedTransactions(unvalidated_txs));
        }

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

        Ok(())
    }
}
