//! Note-related queries and models.

use diesel::prelude::*;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::actor::inflight_note::InflightNetworkNote;
use crate::db::errors::DatabaseError;
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
    pub attempt_count: i32,
    pub last_attempt: Option<i64>,
    pub created_by: Option<Vec<u8>>,
    pub consumed_by: Option<Vec<u8>>,
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
///     (nullifier, account_id, note_data, attempt_count, last_attempt, created_by, consumed_by)
/// VALUES (?1, ?2, ?3, 0, NULL, NULL, NULL)
/// ```
pub fn insert_committed_notes(
    conn: &mut SqliteConnection,
    notes: &[SingleTargetNetworkNote],
) -> Result<(), DatabaseError> {
    for note in notes {
        let row = NoteInsert {
            nullifier: conversions::nullifier_to_bytes(&note.nullifier()),
            account_id: conversions::network_account_id_to_bytes(note.account_id()),
            note_data: conversions::single_target_note_to_bytes(note),
            attempt_count: 0,
            last_attempt: None,
            created_by: None,
            consumed_by: None,
        };
        diesel::replace_into(schema::notes::table).values(&row).execute(conn)?;
    }
    Ok(())
}

/// Returns notes available for consumption by a given account.
///
/// Queries unconsumed notes (`consumed_by IS NULL`) for the account that have not exceeded the
/// maximum attempt count, then applies backoff filtering in Rust via
/// `InflightNetworkNote::is_available`.
///
/// # Raw SQL
///
/// ```sql
/// SELECT note_data, attempt_count, last_attempt
/// FROM notes
/// WHERE
///     account_id = ?1
///     AND consumed_by IS NULL
///     AND attempt_count < ?2
/// ```
#[allow(clippy::cast_possible_wrap)]
pub fn available_notes(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    block_num: BlockNumber,
    max_attempts: usize,
) -> Result<Vec<InflightNetworkNote>, DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);

    // Get unconsumed notes for this account that haven't exceeded the max attempt count.
    let rows: Vec<NoteRow> = schema::notes::table
        .filter(schema::notes::account_id.eq(&account_id_bytes))
        .filter(schema::notes::consumed_by.is_null())
        .filter(schema::notes::attempt_count.lt(max_attempts as i32))
        .select(NoteRow::as_select())
        .load(conn)?;

    let mut result = Vec::new();
    for row in rows {
        #[allow(clippy::cast_sign_loss)]
        let attempt_count = row.attempt_count as usize;
        let note = note_row_to_inflight(
            &row.note_data,
            attempt_count,
            row.last_attempt.map(conversions::block_num_from_i64),
        )?;
        if note.is_available(block_num) {
            result.push(note);
        }
    }

    Ok(result)
}

/// Marks notes as failed by incrementing `attempt_count` and setting `last_attempt`.
///
/// # Raw SQL
///
/// Per nullifier:
///
/// ```sql
/// UPDATE notes
/// SET attempt_count = attempt_count + 1, last_attempt = ?1
/// WHERE nullifier = ?2
/// ```
pub fn notes_failed(
    conn: &mut SqliteConnection,
    nullifiers: &[Nullifier],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = conversions::block_num_to_i64(block_num);

    for nullifier in nullifiers {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);

        diesel::update(schema::notes::table.find(&nullifier_bytes))
            .set((
                schema::notes::attempt_count.eq(schema::notes::attempt_count + 1),
                schema::notes::last_attempt.eq(Some(block_num_val)),
            ))
            .execute(conn)?;
    }
    Ok(())
}

/// Drops notes for the given account that have exceeded the maximum attempt count.
///
/// # Raw SQL
///
/// ```sql
/// DELETE FROM notes
/// WHERE account_id = ?1 AND attempt_count >= ?2
/// ```
#[allow(clippy::cast_possible_wrap)]
pub fn drop_failing_notes(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    max_attempts: usize,
) -> Result<(), DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);
    let max_attempts = max_attempts as i32;

    diesel::delete(
        schema::notes::table
            .filter(schema::notes::account_id.eq(&account_id_bytes))
            .filter(schema::notes::attempt_count.ge(max_attempts)),
    )
    .execute(conn)?;

    Ok(())
}

// HELPERS
// ================================================================================================

/// Constructs an `InflightNetworkNote` from DB row fields.
fn note_row_to_inflight(
    note_data: &[u8],
    attempt_count: usize,
    last_attempt: Option<BlockNumber>,
) -> Result<InflightNetworkNote, DatabaseError> {
    let note = conversions::single_target_note_from_bytes(note_data)?;
    Ok(InflightNetworkNote::from_parts(note, attempt_count, last_attempt))
}
