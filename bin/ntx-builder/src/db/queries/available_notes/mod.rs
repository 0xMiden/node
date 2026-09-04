//! Selects notes available for consumption by a network account.

use miden_node_db::sqlite::ReadTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_standards::note::AccountTargetNetworkNote;

use crate::db::eligibility::{has_backoff_passed, note_recheck_block};

const SQL: &str = include_str!("available_notes.sql");

/// Notes available for consumption by an account, plus the corrections its eligibility filter
/// needs.
pub struct AvailableNotes {
    /// Notes that are eligible for consumption at the queried block.
    pub eligible: Vec<AccountTargetNetworkNote>,
    /// Notes whose stored eligibility block has passed but which the exact hint and backoff check
    /// still rejects, paired with the block they actually become eligible at.
    ///
    /// The caller persists these. Without that write the account keeps being selected for a note
    /// that cannot be attempted (see [`crate::db::eligibility`]).
    pub stale_eligibility: Vec<(Nullifier, BlockNumber)>,
}

/// Returns notes available for consumption by a given account.
#[expect(clippy::cast_possible_wrap)]
pub fn available_notes(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
    max_attempts: usize,
) -> Result<AvailableNotes, DatabaseError> {
    let rows =
        tx.query(SQL, &[&account_id, &(max_attempts as i64), &block_num.to_raw_sql()], |row| {
            Ok((row.get::<Note>(0)?, row.get::<i64>(1)?, row.get::<Option<i64>>(2)?))
        })?;

    let mut eligible = Vec::new();
    let mut stale_eligibility = Vec::new();
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
            stale_eligibility.push((note.as_note().nullifier(), recheck));
        }
    }

    Ok(AvailableNotes { eligible, stale_eligibility })
}
