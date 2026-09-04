//! When a network note becomes eligible for a transaction attempt.
//!
//! Two things delay a note: its execution hint, which opens a window of consumable blocks, and the
//! exponential backoff applied after a failed attempt. This module computes both, and every write
//! path that touches a note stores the result in `notes.next_eligible_block` so the scheduler can
//! ask for the ready accounts with a single indexed query.

use miden_protocol::block::BlockNumber;
use miden_standards::note::NoteExecutionHint;

/// Block number stored for a note that can never become eligible again.
pub const NEVER_ELIGIBLE: BlockNumber = BlockNumber::MAX;

/// Returns the block at which a freshly ingested note becomes eligible.
pub fn first_eligible_block(hint: NoteExecutionHint, created_at: BlockNumber) -> BlockNumber {
    eligible_at_or_after(hint, created_at)
}

/// Returns the block at which a note becomes eligible again after `attempts` failed attempts, the
/// latest of which was recorded at `last_attempt`.
pub fn eligible_block_after_failure(
    hint: NoteExecutionHint,
    attempts: usize,
    last_attempt: BlockNumber,
) -> BlockNumber {
    eligible_at_or_after(hint, backoff_ready_block(Some(last_attempt), attempts))
}

/// Returns the first block at or after `floor` at which the note's execution hint permits
/// consumption.
fn eligible_at_or_after(hint: NoteExecutionHint, floor: BlockNumber) -> BlockNumber {
    hint_next_consumable_block(hint, floor).map_or(floor, |block| block.max(floor))
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
    if !hint_ok && let Some(hint_block) = hint_next_consumable_block(hint, chain_tip) {
        recheck = recheck.max(hint_block);
    }
    recheck
}

/// Returns the first block at or after `from` for which `hint.can_be_consumed` turns true, or
/// `None` when the hint imposes no future-block constraint ([`NoteExecutionHint::None`]/`Always`).
/// leaving the caller's floor in place.
pub fn hint_next_consumable_block(
    hint: NoteExecutionHint,
    from: BlockNumber,
) -> Option<BlockNumber> {
    match hint {
        NoteExecutionHint::None | NoteExecutionHint::Always => None,
        NoteExecutionHint::AfterBlock { block_num } => Some(block_num),
        NoteExecutionHint::OnBlockSlot { round_len, slot_len, slot_offset } => {
            let block = u64::from(from.as_u32());
            // `1 << round_len` as `can_be_consumed` computes it, in u64 to avoid the overflow its
            // u32 shift would hit; bail to the caller's floor for degenerate exponents.
            let round_len_blocks = 1u64.checked_shl(u32::from(round_len))?;
            let slot_len_blocks = 1u64.checked_shl(u32::from(slot_len))?;
            let round_index = block / round_len_blocks;
            let slot_start =
                round_index * round_len_blocks + u64::from(slot_offset) * slot_len_blocks;
            let slot_end = slot_start + slot_len_blocks;
            let next = if block < slot_start {
                slot_start
            } else if block >= slot_end {
                // Past this round's slot; the next opening is the same slot one round later.
                slot_start + round_len_blocks
            } else {
                block
            };
            // Beyond the representable block range the note is effectively never consumable; clamp
            // so the caller schedules at most a far-future recheck rather than wrapping.
            Some(BlockNumber::from(u32::try_from(next).unwrap_or(u32::MAX)))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-forces the first block at or after `from` for which the hint is consumable, by
    /// scanning forward. Used as an independent oracle for [`hint_next_consumable_block`].
    fn brute_force_next(hint: NoteExecutionHint, from: u32) -> Option<u32> {
        (from..=from.saturating_add(4096))
            .find(|&b| hint.can_be_consumed(BlockNumber::from(b)) == Some(true))
    }

    /// [`hint_next_consumable_block`] must agree, block for block, with scanning
    /// [`NoteExecutionHint::can_be_consumed`] forward. This guards against the slot arithmetic
    /// drifting from the protocol definition it mirrors.
    #[test]
    fn hint_next_consumable_block_matches_can_be_consumed() {
        let hints = [
            NoteExecutionHint::after_block(BlockNumber::from(200)),
            NoteExecutionHint::on_block_slot(10, 7, 1),
            NoteExecutionHint::on_block_slot(8, 4, 0),
            NoteExecutionHint::on_block_slot(9, 5, 3),
        ];
        for hint in hints {
            for b in 0u32..1300 {
                // Only meaningful while the note is currently NOT consumable.
                if hint.can_be_consumed(BlockNumber::from(b)) != Some(false) {
                    continue;
                }
                let got = hint_next_consumable_block(hint, BlockNumber::from(b))
                    .expect("a windowed hint must report a next block")
                    .as_u32();
                let expected = brute_force_next(hint, b)
                    .expect("oracle must find a consumable block within the scan window");
                assert_eq!(got, expected, "hint {hint:?} at block {b}");
            }
        }
    }

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

    /// An ingested note is eligible immediately unless its hint says otherwise.
    #[test]
    fn first_eligible_block_follows_the_hint() {
        let created_at = BlockNumber::from(42);

        assert_eq!(
            first_eligible_block(NoteExecutionHint::Always, created_at),
            created_at,
            "an unconstrained note is eligible in the block that created it",
        );
        assert_eq!(
            first_eligible_block(
                NoteExecutionHint::after_block(BlockNumber::from(100)),
                created_at
            ),
            BlockNumber::from(100),
        );
        assert_eq!(
            first_eligible_block(NoteExecutionHint::after_block(BlockNumber::from(7)), created_at),
            created_at,
            "a window that already opened does not move the note into the past",
        );
    }
}
