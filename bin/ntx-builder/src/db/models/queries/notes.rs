//! Note-related queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_standards::note::{AccountTargetNetworkNote, NoteExecutionHint};

use crate::NoteError;
use crate::db::models::conv as conversions;
use crate::db::schema;

// MODELS
// ================================================================================================

/// Row read from `notes`.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NoteRow {
    pub note_data: Vec<u8>,
    pub attempt_count: i32,
    pub last_attempt: Option<i64>,
}

/// Row for inserting into `notes`.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NoteInsert {
    pub nullifier: Vec<u8>,
    pub account_id: Vec<u8>,
    pub note_data: Vec<u8>,
    pub note_id: Option<Vec<u8>>,
    pub attempt_count: i32,
    pub last_attempt: Option<i64>,
    pub last_error: Option<String>,
    pub committed_at: Option<i64>,
}

/// Row returned by `get_note_status()`.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NoteStatusRow {
    pub note_id: Option<Vec<u8>>,
    pub last_error: Option<String>,
    pub attempt_count: i32,
    pub last_attempt: Option<i64>,
    pub committed_at: Option<i64>,
}

// QUERIES
// ================================================================================================

/// Inserts network notes from a committed block. Uses `INSERT OR IGNORE` so re-applying the same
/// block (e.g. on a redelivery from the subscription stream) is a no-op rather than a constraint
/// violation.
pub fn insert_network_notes(
    conn: &mut SqliteConnection,
    notes: &[AccountTargetNetworkNote],
) -> Result<(), DatabaseError> {
    for note in notes {
        let row = NoteInsert {
            nullifier: conversions::nullifier_to_bytes(&note.as_note().nullifier()),
            account_id: conversions::account_id_to_bytes(note.target_account_id()),
            note_data: note.as_note().to_bytes(),
            note_id: Some(conversions::note_id_to_bytes(&note.as_note().id())),
            attempt_count: 0,
            last_attempt: None,
            last_error: None,
            committed_at: None,
        };
        diesel::insert_or_ignore_into(schema::notes::table).values(&row).execute(conn)?;
    }
    Ok(())
}

/// Marks notes as consumed by setting `committed_at` to the block number whose committed body
/// contained their nullifier. Rows for nullifiers we never inserted (notes whose targets are not
/// network accounts, or notes that arrived before our subscription cursor) are silently skipped.
///
/// Rows are kept around (not deleted) so the `GetNetworkNoteStatus` endpoint can report the full
/// lifecycle of any note the ntx-builder has ever seen.
pub fn mark_notes_consumed(
    conn: &mut SqliteConnection,
    nullifiers: &[Nullifier],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = conversions::block_num_to_i64(block_num);
    for nullifier in nullifiers {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);
        diesel::update(schema::notes::table.find(&nullifier_bytes))
            .filter(schema::notes::committed_at.is_null())
            .set(schema::notes::committed_at.eq(Some(block_num_val)))
            .execute(conn)?;
    }
    Ok(())
}

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
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    max_attempts: usize,
) -> Result<AvailableNotes, DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);

    let rows: Vec<NoteRow> = schema::notes::table
        .filter(schema::notes::account_id.eq(&account_id_bytes))
        .filter(schema::notes::committed_at.is_null())
        .filter(schema::notes::attempt_count.lt(max_attempts as i32))
        .select(NoteRow::as_select())
        .load(conn)?;

    let mut eligible = Vec::new();
    let mut next_retry_block: Option<BlockNumber> = None;
    for row in rows {
        #[expect(clippy::cast_sign_loss)]
        let attempt_count = row.attempt_count as usize;
        let last_attempt = row.last_attempt.map(conversions::block_num_from_i64);
        let note = deserialize_note(&row.note_data)?;

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

/// Marks notes as failed by incrementing `attempt_count`, setting `last_attempt`, and storing the
/// latest error message.
pub fn notes_failed(
    conn: &mut SqliteConnection,
    failed_notes: &[(Nullifier, NoteError)],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = conversions::block_num_to_i64(block_num);

    for (nullifier, error) in failed_notes {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);
        let error_report = error.as_report();

        diesel::update(schema::notes::table.find(&nullifier_bytes))
            .set((
                schema::notes::attempt_count.eq(schema::notes::attempt_count + 1),
                schema::notes::last_attempt.eq(Some(block_num_val)),
                schema::notes::last_error.eq(Some(error_report)),
            ))
            .execute(conn)?;
    }
    Ok(())
}

/// Returns the status for a note identified by its note ID.
pub fn get_note_status(
    conn: &mut SqliteConnection,
    note_id_bytes: &[u8],
) -> Result<Option<NoteStatusRow>, DatabaseError> {
    schema::notes::table
        .filter(schema::notes::note_id.eq(note_id_bytes))
        .select(NoteStatusRow::as_select())
        .first(conn)
        .optional()
        .map_err(Into::into)
}

/// Returns the distinct set of network accounts that currently have at least one pending note
/// (unconsumed and within the per-note attempt budget).
#[expect(clippy::cast_possible_wrap)]
pub fn accounts_with_pending_notes(
    conn: &mut SqliteConnection,
    max_attempts: usize,
) -> Result<Vec<AccountId>, DatabaseError> {
    let account_id_blobs: Vec<Vec<u8>> = schema::notes::table
        .filter(schema::notes::committed_at.is_null())
        .filter(schema::notes::attempt_count.lt(max_attempts as i32))
        .select(schema::notes::account_id)
        .distinct()
        .load(conn)?;

    account_id_blobs
        .iter()
        .map(|bytes| conversions::account_id_from_bytes(bytes))
        .collect()
}

/// Returns `true` if the account has any pending note: unconsumed and within the per-note attempt
/// budget. This is the cheap equivalent of "does [`available_notes`] return a note that is eligible
/// or awaiting a retry window" (every row passing this filter is one or the other), but it tests
/// for existence in SQL and deserializes nothing. The coordinator uses it to decide whether to
/// respawn an actor that just idle-timed-out.
#[expect(clippy::cast_possible_wrap)]
pub fn account_has_pending_notes(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    max_attempts: usize,
) -> Result<bool, DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);
    let pending = diesel::select(diesel::dsl::exists(
        schema::notes::table
            .filter(schema::notes::account_id.eq(&account_id_bytes))
            .filter(schema::notes::committed_at.is_null())
            .filter(schema::notes::attempt_count.lt(max_attempts as i32)),
    ))
    .get_result(conn)?;
    Ok(pending)
}

// HELPERS
// ================================================================================================

/// Deserializes an [`AccountTargetNetworkNote`] from raw note bytes.
fn deserialize_note(note_data: &[u8]) -> Result<AccountTargetNetworkNote, DatabaseError> {
    let note = Note::read_from_bytes(note_data)
        .map_err(|source| DatabaseError::deserialization("failed to parse note", source))?;
    AccountTargetNetworkNote::new(note).map_err(|source| {
        DatabaseError::deserialization("failed to convert to network note", source)
    })
}

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
/// mirrors `can_be_consumed`; the `notes::tests` module cross-checks the two against each other.
/// Degenerate round/slot exponents that would overflow are treated as "no exact answer" (`None`),
/// leaving the caller's next-block default.
fn hint_next_consumable_block(hint: NoteExecutionHint, from: BlockNumber) -> Option<BlockNumber> {
    match hint {
        NoteExecutionHint::None | NoteExecutionHint::Always => None,
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
