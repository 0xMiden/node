//! Note-related queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_standards::note::AccountTargetNetworkNote;

use crate::NoteError;
use crate::db::models::conv as conversions;
use crate::db::schema;

// MODELS
// ================================================================================================

/// Row read from the unified `notes` table.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NoteRow {
    pub note_data: Vec<u8>,
    pub attempt_count: i32,
    pub last_attempt: Option<i64>,
}

/// Row for inserting into the unified `notes` table.
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
    pub created_by: Option<Vec<u8>>,
    pub consumed_by: Option<Vec<u8>>,
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
    pub consumed_by: Option<Vec<u8>>,
    pub committed_at: Option<i64>,
}

// QUERIES
// ================================================================================================

/// Batch inserts committed notes (`created_by = NULL`, `consumed_by = NULL`).
///
/// # Raw SQL
///
/// Per note:
///
/// ```sql
/// INSERT OR REPLACE INTO notes
///     (nullifier, account_id, note_data, note_id, attempt_count, last_attempt, last_error,
///      created_by, consumed_by)
/// VALUES (?1, ?2, ?3, ?4, 0, NULL, NULL, NULL, NULL)
/// ```
pub fn insert_committed_notes(
    conn: &mut SqliteConnection,
    notes: &[AccountTargetNetworkNote],
) -> Result<(), DatabaseError> {
    for note in notes {
        let row = NoteInsert {
            nullifier: conversions::nullifier_to_bytes(&note.as_note().nullifier()),
            account_id: conversions::network_account_id_to_bytes(NetworkAccountId::new_trusted(
                note.target_account_id(),
            )),
            note_data: note.as_note().to_bytes(),
            note_id: Some(conversions::note_id_to_bytes(&note.as_note().id())),
            attempt_count: 0,
            last_attempt: None,
            last_error: None,
            created_by: None,
            consumed_by: None,
            committed_at: None,
        };
        diesel::replace_into(schema::notes::table).values(&row).execute(conn)?;
    }
    Ok(())
}

/// Returns notes available for consumption by a given account.
///
/// Queries unconsumed notes (`consumed_by IS NULL`) for the account that have not exceeded the
/// maximum attempt count, then applies backoff and execution hint filtering in Rust.
///
/// # Raw SQL
///
/// ```sql
/// SELECT note_data, attempt_count, last_attempt
/// FROM notes
/// WHERE
///     account_id = ?1
///     AND consumed_by IS NULL
///     AND committed_at IS NULL
///     AND attempt_count < ?2
/// ```
#[expect(clippy::cast_possible_wrap)]
pub fn available_notes(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    block_num: BlockNumber,
    max_attempts: usize,
) -> Result<Vec<AccountTargetNetworkNote>, DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);

    // Get unconsumed, uncommitted notes for this account that haven't exceeded the max attempt
    // count.
    let rows: Vec<NoteRow> = schema::notes::table
        .filter(schema::notes::account_id.eq(&account_id_bytes))
        .filter(schema::notes::consumed_by.is_null())
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

/// Marks notes as failed by incrementing `attempt_count`, setting `last_attempt`, and storing
/// the latest error message.
///
/// # Raw SQL
///
/// Per nullifier:
///
/// ```sql
/// UPDATE notes
/// SET attempt_count = attempt_count + 1, last_attempt = ?1, last_error = ?2
/// WHERE nullifier = ?3
/// ```
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
///
/// # Raw SQL
///
/// ```sql
/// SELECT note_id, last_error, attempt_count, last_attempt, consumed_by
/// FROM notes
/// WHERE note_id = ?1
/// ```
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
