use std::time::{SystemTime, UNIX_EPOCH};

use miden_node_tracing::{ErrorReport, instrument, miden_span_record};
use miden_protocol::block::{BlockBody, BlockHeader};
use miden_protocol::transaction::TransactionHeader;

use super::{ValidatorError, ValidatorService};

/// Maximum time a proposal may lead the validator's clock to allow for operator clock skew.
const MAX_BLOCK_FUTURE_SKEW_SECS: u64 = 60;

/// Rejects proposals beyond the local clock-skew allowance before signing or catch-up.
pub(super) fn validate_timestamp(timestamp: u32) -> Result<(), ValidatorError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ValidatorError::ClockBeforeUnixEpoch)?
        .as_secs();
    let latest_timestamp = now + MAX_BLOCK_FUTURE_SKEW_SECS;
    if u64::from(timestamp) > latest_timestamp {
        return Err(ValidatorError::BlockTimestampTooFarInFuture { timestamp, latest_timestamp });
    }

    Ok(())
}

impl ValidatorService {
    /// Verifies the transaction IDs and parent against local state, and checks that the parent
    /// authorizes the signing key. Returns whether accepting this block confirms a validator quorum
    /// change in its parent.
    #[instrument(err)]
    pub(super) async fn validate_block(
        &self,
        proposed_header: &BlockHeader,
        proposed_body: &BlockBody,
        chain: &crate::db::ChainState,
    ) -> Result<bool, ValidatorError> {
        let latest = chain.pending.as_ref().unwrap_or(&chain.tip);
        miden_span_record!(tip.number = chain.tip.block_num());

        // Search for any proposed transactions that have not previously been validated.
        let proposed_tx_ids = proposed_body
            .transactions()
            .as_slice()
            .iter()
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

        let prev = if proposed_header.block_num() == latest.block_num() {
            if chain.pending.is_none() {
                return Err(if latest.block_num().as_u32() == 0 {
                    ValidatorError::CannotReplaceGenesis
                } else {
                    ValidatorError::CannotReplaceConfirmedBlock
                });
            }
            &chain.tip
        } else {
            // Proposed block is a new block. Block number must be sequential.
            let expected_block_num = latest.block_num().child();
            if proposed_header.block_num() != expected_block_num {
                return Err(ValidatorError::BlockNumberMismatch {
                    expected: expected_block_num,
                    actual: proposed_header.block_num(),
                });
            }
            latest
        };

        // A proposal must reference the confirmed tip when replacing the pending block, or the
        // pending block when extending it.
        if proposed_header.prev_block_commitment() != prev.commitment() {
            return Err(ValidatorError::PrevBlockCommitmentMismatch);
        }

        if proposed_header.validator_config().keys() != prev.validator_config().keys() {
            return Err(ValidatorError::ValidatorKeySetChange);
        }

        if proposed_header.validator_config().quorum() != prev.validator_config().quorum() {
            let pending = self
                .db
                .read("pending_validator_quorum", |tx| tx.select_pending_validator_quorum())
                .await
                .map_err(ValidatorError::DatabaseError)?;
            if pending != Some(proposed_header.validator_config().quorum()) {
                return Err(ValidatorError::UnregisteredValidatorQuorum);
            }
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

        Ok(prev.validator_config().quorum() != chain.tip.validator_config().quorum())
    }
}

impl ValidatorError {
    pub(super) fn into_validation_status(self) -> tonic::Status {
        let message = self.as_report_context("Failed to validate block");
        match self {
            Self::UnvalidatedTransactions(_)
            | Self::BlockTimestampTooFarInFuture { .. }
            | Self::BlockNumberMismatch { .. }
            | Self::UnregisteredValidatorQuorum
            | Self::ValidatorKeySetChange
            | Self::CannotReplaceConfirmedBlock
            | Self::CannotReplaceGenesis
            | Self::PrevBlockCommitmentMismatch
            | Self::ValidatorKeyNotInSet { .. } => tonic::Status::invalid_argument(message),
            _ => tonic::Status::internal(message),
        }
    }
}
