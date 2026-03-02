use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;

// INFLIGHT NETWORK NOTE
// ================================================================================================

/// An unconsumed network note that may have failed to execute.
///
/// The block number at which the network note was attempted are approximate and may not
/// reflect the exact block number for which the execution attempt failed. The actual block
/// will likely be soon after the number that is recorded here.
#[derive(Debug, Clone)]
pub struct InflightNetworkNote {
    note: SingleTargetNetworkNote,
    attempt_count: usize,
    last_attempt: Option<BlockNumber>,
}

impl InflightNetworkNote {
    /// Creates a new inflight network note.
    pub fn new(note: SingleTargetNetworkNote) -> Self {
        Self {
            note,
            attempt_count: 0,
            last_attempt: None,
        }
    }

    /// Reconstructs an inflight network note from its constituent parts (e.g., from DB rows).
    pub fn from_parts(
        note: SingleTargetNetworkNote,
        attempt_count: usize,
        last_attempt: Option<BlockNumber>,
    ) -> Self {
        Self { note, attempt_count, last_attempt }
    }

    /// Consumes the inflight network note and returns the inner network note.
    pub fn into_inner(self) -> SingleTargetNetworkNote {
        self.note
    }

    /// Returns a reference to the inner network note.
    pub fn to_inner(&self) -> &SingleTargetNetworkNote {
        &self.note
    }

    /// Returns the number of attempts made to execute the network note.
    pub fn attempt_count(&self) -> usize {
        self.attempt_count
    }

    /// Checks if the network note is available for execution.
    ///
    /// The note is available if the backoff period has passed.
    pub fn is_available(&self, block_num: BlockNumber) -> bool {
        self.note.can_be_consumed(block_num).unwrap_or(true)
            && has_backoff_passed(block_num, self.last_attempt, self.attempt_count)
    }

    /// Registers a failed attempt to execute the network note at the specified block number.
    pub fn fail(&mut self, block_num: BlockNumber) {
        self.last_attempt = Some(block_num);
        self.attempt_count += 1;
    }
}

impl From<InflightNetworkNote> for Note {
    fn from(value: InflightNetworkNote) -> Self {
        value.into_inner().into()
    }
}

// HELPERS
// ================================================================================================

/// Checks if the backoff block period has passed.
///
/// The number of blocks passed since the last attempt must be greater than or equal to
/// e^(0.25 * `attempt_count`) rounded to the nearest integer.
///
/// This evaluates to the following:
/// - After 1 attempt, the backoff period is 1 block.
/// - After 3 attempts, the backoff period is 2 blocks.
/// - After 10 attempts, the backoff period is 12 blocks.
/// - After 20 attempts, the backoff period is 148 blocks.
/// - etc...
#[expect(clippy::cast_precision_loss, clippy::cast_sign_loss)]
fn has_backoff_passed(
    chain_tip: BlockNumber,
    last_attempt: Option<BlockNumber>,
    attempts: usize,
) -> bool {
    if attempts == 0 {
        return true;
    }
    // Compute the number of blocks passed since the last attempt.
    let blocks_passed = last_attempt
        .and_then(|last| chain_tip.checked_sub(last.as_u32()))
        .unwrap_or_default();

    // Compute the exponential backoff threshold: Δ = e^(0.25 * n).
    let backoff_threshold = (0.25 * attempts as f64).exp().round() as usize;

    // Check if the backoff period has passed.
    blocks_passed.as_usize() > backoff_threshold
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    use super::has_backoff_passed;

    #[rstest::rstest]
    #[test]
    #[case::all_zero(Some(BlockNumber::GENESIS), BlockNumber::GENESIS, 0, true)]
    #[case::no_attempts(None, BlockNumber::GENESIS, 0, true)]
    #[case::one_attempt(Some(BlockNumber::GENESIS), BlockNumber::from(2), 1, true)]
    #[case::three_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(3), 3, true)]
    #[case::ten_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(13), 10, true)]
    #[case::twenty_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(149), 20, true)]
    #[case::one_attempt_false(Some(BlockNumber::GENESIS), BlockNumber::from(1), 1, false)]
    #[case::three_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(2), 3, false)]
    #[case::ten_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(12), 10, false)]
    #[case::twenty_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(148), 20, false)]
    fn backoff_has_passed(
        #[case] last_attempt_block_num: Option<BlockNumber>,
        #[case] current_block_num: BlockNumber,
        #[case] attempt_count: usize,
        #[case] backoff_should_have_passed: bool,
    ) {
        assert_eq!(
            backoff_should_have_passed,
            has_backoff_passed(current_block_num, last_attempt_block_num, attempt_count)
        );
    }
}
