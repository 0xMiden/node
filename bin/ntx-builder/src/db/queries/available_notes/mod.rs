//! Selects notes available for consumption by a network account.

use miden_node_db::sqlite::ReadTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;
use miden_standards::note::AccountTargetNetworkNote;

use crate::db::eligibility::{has_backoff_passed, note_recheck_block};

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
