//! Note-related queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_standards::note::AccountTargetNetworkNote;

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
    pub received_at_block: i64,
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
///
/// `block_num` is the block in which the notes were observed; it is recorded as `received_at_block`
/// so the event loop can age-expire notes that stay pending for too many blocks.
pub fn insert_network_notes(
    conn: &mut SqliteConnection,
    notes: &[AccountTargetNetworkNote],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let received_at_block = conversions::block_num_to_i64(block_num);
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
            received_at_block,
        };
        diesel::insert_or_ignore_into(schema::notes::table).values(&row).execute(conn)?;
    }
    Ok(())
}

/// Deletes still-pending notes that were first observed more than `retention_blocks` blocks before
/// `chain_tip`.
///
/// The ntx-builder persists every network note from a committed block, including notes targeting
/// accounts it does not (yet) track. Notes whose target account is never created as a network
/// account can never be consumed, so without this sweep they would accumulate forever. Notes that
/// have already been consumed (`committed_at` set) are retained for `GetNetworkNoteStatus` lifecycle
/// reporting and are never touched here.
///
/// Returns the number of rows deleted.
///
/// # Raw SQL
///
/// ```sql
/// DELETE FROM notes
/// WHERE committed_at IS NULL AND received_at_block < ?1
/// ```
pub fn delete_expired_pending_notes(
    conn: &mut SqliteConnection,
    chain_tip: BlockNumber,
    retention_blocks: u32,
) -> Result<usize, DatabaseError> {
    // Saturating: until the chain advances past the retention window there is nothing old enough to
    // expire, so the cutoff is clamped at 0 (notes received at block 0 are not `< 0`).
    let cutoff = chain_tip.as_u32().saturating_sub(retention_blocks);
    let cutoff = conversions::block_num_to_i64(BlockNumber::from(cutoff));

    let deleted = diesel::delete(
        schema::notes::table
            .filter(schema::notes::committed_at.is_null())
            .filter(schema::notes::received_at_block.lt(cutoff)),
    )
    .execute(conn)?;

    Ok(deleted)
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

/// Returns notes available for consumption by a given account.
///
/// Selects unconsumed notes for the account (a row exists only while a note is unconsumed) whose
/// `attempt_count` is below the cap, then applies execution-hint and backoff filtering in Rust.
#[expect(clippy::cast_possible_wrap)]
pub fn available_notes(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    max_attempts: usize,
) -> Result<Vec<AccountTargetNetworkNote>, DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);

    let rows: Vec<NoteRow> = schema::notes::table
        .filter(schema::notes::account_id.eq(&account_id_bytes))
        .filter(schema::notes::committed_at.is_null())
        .filter(schema::notes::attempt_count.lt(max_attempts as i32))
        .select(NoteRow::as_select())
        .load(conn)?;

    let mut result = Vec::new();
    for row in rows {
        #[expect(clippy::cast_sign_loss)]
        let attempt_count = row.attempt_count as usize;
        let last_attempt = row.last_attempt.map(conversions::block_num_from_i64);
        let note = deserialize_note(&row.note_data)?;

        let execution_hint_ok = note.execution_hint().can_be_consumed(block_num).unwrap_or(true);
        if execution_hint_ok && has_backoff_passed(block_num, last_attempt, attempt_count) {
            result.push(note);
        }
    }

    Ok(result)
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
