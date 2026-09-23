//! Selects notes available for consumption by a network account.

use miden_node_db::sqlite::ReadTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;
use miden_standards::note::{AccountTargetNetworkNote, NoteExecutionHint};

const SQL: &str = include_str!("available_notes.sql");

/// Notes available for consumption by an account, plus a hint for when to look again.
pub struct AvailableNotes {
    /// Notes that are eligible for consumption at the queried block.
    pub eligible: Vec<AccountTargetNetworkNote>,
    /// Earliest block at which a currently-ineligible (but still alive) note becomes eligible,
    /// or `None` if the account has no pending notes awaiting backoff or an execution-hint window.
    ///
    /// Actors use this to avoid re-querying the DB on every block: a `NoViableNotes` actor only
    /// re-selects once the chain tip reaches this block (or a new note arrives), and an actor with
    /// `None` here has no pending notes at all and may deactivate on idle timeout.
    pub next_retry_block: Option<BlockNumber>,
}

/// Returns notes available for consumption by a given account.
///
/// Selects unconsumed notes for the account (a row exists only while a note is unconsumed) whose
/// `attempt_count` is below the cap, then applies execution-hint and backoff filtering in Rust.
/// Notes filtered out by backoff or an execution-hint window are still alive and become eligible at
/// a later block; the earliest such block is returned as [`AvailableNotes::next_retry_block`] so the
/// caller can schedule a single re-check instead of polling every block.
#[expect(clippy::cast_possible_wrap)]
pub fn available_notes(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
    max_attempts: usize,
) -> Result<AvailableNotes, DatabaseError> {
    let rows = tx.query(SQL, &[&account_id, &(max_attempts as i64)], |row| {
        Ok((row.get::<Note>(0)?, row.get::<i64>(1)?, row.get::<Option<i64>>(2)?))
    })?;

    let mut eligible = Vec::new();
    let mut next_retry_block: Option<BlockNumber> = None;
    for (note, attempt_count, last_attempt) in rows {
        #[expect(clippy::cast_sign_loss)]
        let attempt_count = attempt_count as usize;
        let last_attempt = last_attempt.map(BlockNumber::from_raw_sql).transpose()?;
        let note = AccountTargetNetworkNote::new(note).map_err(|source| {
            DatabaseError::deserialization("failed to convert to network note", source)
        })?;

        let hint = note.execution_hint();
        let hint_ok = hint.can_be_consumed(block_num).unwrap_or(true);
        let backoff_ok = has_backoff_passed(block_num, last_attempt, attempt_count);
        if hint_ok && backoff_ok {
            eligible.push(note);
        } else {
            let recheck = note_recheck_block(
                hint,
                block_num,
                last_attempt,
                attempt_count,
                backoff_ok,
                hint_ok,
            );
            next_retry_block =
                Some(next_retry_block.map_or(recheck, |earliest| earliest.min(recheck)));
        }
    }

    Ok(AvailableNotes { eligible, next_retry_block })
}

// HELPERS
// ================================================================================================

/// Checks if the backoff block period has passed.
///
/// The number of blocks passed since the last attempt must be greater than or equal to
/// e^(0.25 * `attempt_count`) rounded to the nearest integer.
#[expect(clippy::cast_precision_loss, clippy::cast_sign_loss)]
fn has_backoff_passed(
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
///
/// Inverts [`has_backoff_passed`], which is satisfied once `chain_tip - last_attempt` exceeds the
/// threshold, so the first eligible tip is `last_attempt + threshold + 1`. Only meaningful when the
/// note has been attempted (`attempts > 0`); for an unattempted note backoff is always passed.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn backoff_ready_block(last_attempt: Option<BlockNumber>, attempts: usize) -> BlockNumber {
    let last = last_attempt.unwrap_or(BlockNumber::GENESIS);
    let threshold = (0.25 * attempts as f64).exp().round() as u32;
    last + threshold + 1
}

/// Returns the earliest block worth re-checking a currently-ineligible note at.
///
/// The result is at least the next block (so it always lies in the future) and accounts for the
/// reasons the note is ineligible: backoff is inverted exactly via [`backoff_ready_block`], and the
/// execution-hint window is inverted exactly via [`hint_next_consumable_block`]. Inverting the hint
/// exactly (rather than re-checking every block) lets an actor with only a window-pending note wait
/// for that block and idle-deactivate in between, instead of querying the DB on every block.
fn note_recheck_block(
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

/// Returns the first block at or after `from` for which `hint.can_be_consumed` turns true, or `None`
/// when the hint imposes no future-block constraint ([`NoteExecutionHint::None`]/`Always`).
///
/// This is the exact inverse of [`NoteExecutionHint::can_be_consumed`]: `AfterBlock` opens at its
/// block, and the periodic `OnBlockSlot` window opens either later this round (if `from` precedes
/// the slot) or at the same slot in the next round (if `from` is past it). The slot arithmetic
/// mirrors `can_be_consumed`; the `tests` module cross-checks the two against each other.
/// Degenerate round/slot exponents that would overflow are treated as "no exact answer" (`None`),
/// leaving the caller's next-block default.
fn hint_next_consumable_block(hint: NoteExecutionHint, from: BlockNumber) -> Option<BlockNumber> {
    match hint {
        NoteExecutionHint::None | NoteExecutionHint::Always | NoteExecutionHint::Unknown(_) => None,
        NoteExecutionHint::AfterBlock { block_num } => Some(block_num),
        NoteExecutionHint::OnBlockSlot { round_len, slot_len, slot_offset } => {
            let block = u64::from(from.as_u32());
            // `1 << round_len` as `can_be_consumed` computes it, in u64 to avoid the overflow its
            // u32 shift would hit; bail to the next-block default for degenerate exponents.
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
    use miden_protocol::block::BlockNumber;
    use miden_standards::note::NoteExecutionHint;

    use super::{has_backoff_passed, hint_next_consumable_block};

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
            NoteExecutionHint::on_block_slot(10, 7, 1), // blocks 128..256, 1152..1280, ...
            NoteExecutionHint::on_block_slot(8, 4, 0),  // blocks 0..16, 256..272, ...
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
}
