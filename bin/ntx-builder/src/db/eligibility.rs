//! When a network note becomes eligible for a transaction attempt.
//!
//! Two things delay a note: its execution hint, which sets the first block at which the note may be
//! consumed, and the exponential backoff applied after a failed attempt. This module computes both,
//! and every write path that touches a note stores the result in `notes.next_eligible_block` so the
//! scheduler can ask for the ready accounts with a single indexed query.

use miden_protocol::block::BlockNumber;
use miden_standards::note::NoteExecutionHint;

/// Block number stored for a note that can never become eligible again.
pub const NEVER_ELIGIBLE: BlockNumber = BlockNumber::MAX;

/// Returns the block at which a note becomes eligible again after `attempts` failed attempts, the
/// latest of which was recorded at `last_attempt`.
pub fn eligible_block_after_failure(
    hint: NoteExecutionHint,
    attempts: usize,
    last_attempt: BlockNumber,
) -> BlockNumber {
    hint_floor(hint).max(backoff_ready_block(Some(last_attempt), attempts))
}

/// Checks if the backoff block period has passed.
#[expect(clippy::cast_precision_loss, clippy::cast_sign_loss)]
pub fn has_backoff_passed(
    chain_tip: BlockNumber,
    last_attempt: Option<BlockNumber>,
    attempts: usize,
) -> bool {
    if attempts == 0 {
        return true;
    }
    let blocks_passed = last_attempt
        .and_then(|last| chain_tip.checked_sub(last.as_u32()))
        .unwrap_or_default();

    let backoff_threshold = (0.25 * attempts as f64).exp().round() as usize;

    blocks_passed.as_usize() > backoff_threshold
}

/// Returns the first block at which a note's backoff period elapses.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
pub fn backoff_ready_block(last_attempt: Option<BlockNumber>, attempts: usize) -> BlockNumber {
    if attempts == 0 {
        return last_attempt.unwrap_or(BlockNumber::GENESIS);
    }
    let last = last_attempt.unwrap_or(BlockNumber::GENESIS);
    let threshold = (0.25 * attempts as f64).exp().round() as u32;
    last + threshold + 1
}

/// Returns the earliest block worth re-checking a currently-ineligible note at.
pub fn note_recheck_block(
    hint: NoteExecutionHint,
    chain_tip: BlockNumber,
    last_attempt: Option<BlockNumber>,
    attempts: usize,
    backoff_ok: bool,
    hint_ok: bool,
) -> BlockNumber {
    let mut recheck = chain_tip.child();
    if !backoff_ok {
        recheck = recheck.max(backoff_ready_block(last_attempt, attempts));
    }
    if !hint_ok {
        recheck = recheck.max(hint_floor(hint));
    }
    recheck
}

/// Returns the first block at which the execution hint permits consumption.
pub fn hint_floor(hint: NoteExecutionHint) -> BlockNumber {
    match hint {
        NoteExecutionHint::None | NoteExecutionHint::Always => BlockNumber::GENESIS,
        NoteExecutionHint::AfterBlock { block_num } => block_num,
        NoteExecutionHint::OnBlockSlot { .. } => NEVER_ELIGIBLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The block stored after a failure is exactly the first block at which the read-time backoff
    /// check passes. This is what lets the stored column stand in for the check.
    #[rstest::rstest]
    #[test]
    #[case(1)]
    #[case(3)]
    #[case(10)]
    #[case(20)]
    fn stored_block_after_failure_matches_the_backoff_check(#[case] attempts: usize) {
        let last_attempt = BlockNumber::from(100);
        let stored =
            eligible_block_after_failure(NoteExecutionHint::Always, attempts, last_attempt);

        assert!(
            has_backoff_passed(stored, Some(last_attempt), attempts),
            "the stored block must satisfy the backoff check",
        );
        assert!(
            !has_backoff_passed(
                stored.parent().expect("the stored block is past genesis"),
                Some(last_attempt),
                attempts
            ),
            "no earlier block may satisfy it, or the stored value would hide the note",
        );
    }

    /// A hint window that opens later than the backoff wins, and vice versa: the note is eligible
    /// only once both allow it.
    #[test]
    fn stored_block_takes_the_later_of_backoff_and_hint() {
        let last_attempt = BlockNumber::from(10);

        let hint = NoteExecutionHint::after_block(BlockNumber::from(500));
        assert_eq!(eligible_block_after_failure(hint, 1, last_attempt), BlockNumber::from(500),);

        let hint = NoteExecutionHint::after_block(BlockNumber::from(1));
        assert_eq!(
            eligible_block_after_failure(hint, 1, last_attempt),
            backoff_ready_block(Some(last_attempt), 1),
        );
    }
}
