//! Note-related queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_standards::note::AccountTargetNetworkNote;
use miden_tx::utils::{Deserializable, Serializable};

use crate::db::models::conv as conversions;
use crate::db::schema;
use crate::inflight_note::InflightNetworkNote;

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
}

/// Row returned by `get_note_error()`.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NoteErrorRow {
    pub note_id: Option<Vec<u8>>,
    pub last_error: Option<String>,
    pub attempt_count: i32,
    pub last_attempt: Option<i64>,
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
            account_id: conversions::network_account_id_to_bytes(
                NetworkAccountId::try_from(note.target_account_id())
                    .expect("account ID of a network note should be a network account"),
            ),
            note_data: note.as_note().to_bytes(),
            note_id: Some(conversions::note_id_to_bytes(&note.as_note().id())),
            attempt_count: 0,
            last_attempt: None,
            last_error: None,
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
#[expect(clippy::cast_possible_wrap)]
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
        #[expect(clippy::cast_sign_loss)]
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
    failed_notes: &[(Nullifier, String)],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = conversions::block_num_to_i64(block_num);

    for (nullifier, error) in failed_notes {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);

        diesel::update(schema::notes::table.find(&nullifier_bytes))
            .set((
                schema::notes::attempt_count.eq(schema::notes::attempt_count + 1),
                schema::notes::last_attempt.eq(Some(block_num_val)),
                schema::notes::last_error.eq(Some(error)),
            ))
            .execute(conn)?;
    }
    Ok(())
}

/// Returns the latest execution error for a note identified by its note ID.
///
/// # Raw SQL
///
/// ```sql
/// SELECT note_id, last_error, attempt_count, last_attempt
/// FROM notes
/// WHERE note_id = ?1
/// ```
pub fn get_note_error(
    conn: &mut SqliteConnection,
    note_id_bytes: &[u8],
) -> Result<Option<NoteErrorRow>, DatabaseError> {
    schema::notes::table
        .filter(schema::notes::note_id.eq(note_id_bytes))
        .select(NoteErrorRow::as_select())
        .first(conn)
        .optional()
        .map_err(Into::into)
}

// HELPERS
// ================================================================================================

/// Constructs an `InflightNetworkNote` from DB row fields.
fn note_row_to_inflight(
    note_data: &[u8],
    attempt_count: usize,
    last_attempt: Option<BlockNumber>,
) -> Result<InflightNetworkNote, DatabaseError> {
    let note = Note::read_from_bytes(note_data)
        .map_err(|source| DatabaseError::deserialization("failed to parse note", source))?;
    let note = AccountTargetNetworkNote::new(note).map_err(|source| {
        DatabaseError::deserialization("failed to convert to network note", source)
    })?;

    Ok(InflightNetworkNote::from_parts(note, attempt_count, last_attempt))
}
