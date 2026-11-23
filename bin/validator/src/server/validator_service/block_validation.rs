use std::time::{SystemTime, UNIX_EPOCH};

use miden_node_tracing::{ErrorReport, instrument, miden_span_record};
use miden_protocol::block::{BlockBody, BlockHeader};
use miden_protocol::transaction::TransactionHeader;

use super::{ValidatorError, ValidatorService};

/// Maximum time a proposal may lead the validator's clock to allow for operator clock skew.
const MAX_BLOCK_FUTURE_SKEW_SECS: u64 = 60;

impl ValidatorService {
    /// Checks the timestamp against the validator's clock, verifies the transaction IDs and parent
    /// against local state, and checks that the parent authorizes the signing key. Returns whether
    /// the proposed header changes the validator configuration at the signed tip.
    #[instrument(err)]
    pub(super) async fn validate_block(
        &self,
        proposed_header: &BlockHeader,
        proposed_body: &BlockBody,
    ) -> Result<bool, ValidatorError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(ValidatorError::ClockBeforeUnixEpoch)?
            .as_secs();
        let timestamp = proposed_header.timestamp();
        let latest_timestamp = now + MAX_BLOCK_FUTURE_SKEW_SECS;
        if u64::from(timestamp) > latest_timestamp {
            return Err(ValidatorError::BlockTimestampTooFarInFuture {
                timestamp,
                latest_timestamp,
            });
        }

        let chain_tip = self
            .db
            .load_chain_tip()
            .await
            .map_err(ValidatorError::DatabaseError)?
            .ok_or(ValidatorError::NoChainTip)?;
        miden_span_record!(tip.number = chain_tip.block_num());

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

        let changes_validator_config =
            proposed_header.validator_config() != chain_tip.validator_config();
        let prev = if proposed_header.block_num() == chain_tip.block_num() {
            // Replacements are rare, so load the tip's parent on demand. An ordinary extension
            // needs only the tip header.
            let prev_block_num =
                chain_tip.block_num().parent().ok_or(ValidatorError::CannotReplaceGenesis)?;
            let parent = self
                .db
                .load_block_header(prev_block_num)
                .await
                .map_err(ValidatorError::DatabaseError)?
                .ok_or(ValidatorError::NoPrevBlockHeader)?;
            // Replacing a block that changed the validator configuration must preserve that
            // configuration.
            if changes_validator_config && parent.validator_config() != chain_tip.validator_config()
            {
                return Err(ValidatorError::CannotReplaceValidatorConfigChange);
            }
            parent
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

        if changes_validator_config {
            let pending = self
                .db
                .read("pending_validator_config", |tx| tx.select_pending_validator_config())
                .await
                .map_err(ValidatorError::DatabaseError)?;
            if pending.as_ref() != Some(proposed_header.validator_config()) {
                return Err(ValidatorError::UnapprovedValidatorConfig);
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

        Ok(changes_validator_config)
    }
}

impl ValidatorError {
    pub(super) fn into_validation_status(self) -> tonic::Status {
        let message = self.as_report_context("Failed to validate block");
        match self {
            Self::UnvalidatedTransactions(_)
            | Self::BlockTimestampTooFarInFuture { .. }
            | Self::BlockNumberMismatch { .. }
            | Self::UnapprovedValidatorConfig
            | Self::CannotReplaceValidatorConfigChange
            | Self::CannotReplaceGenesis
            | Self::PrevBlockCommitmentMismatch
            | Self::ValidatorKeyNotInSet { .. } => tonic::Status::invalid_argument(message),
            _ => tonic::Status::internal(message),
        }
    }
}
