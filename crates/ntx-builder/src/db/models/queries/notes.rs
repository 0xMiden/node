//! Note-related queries and models.

use std::collections::HashSet;

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

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::committed_notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct CommittedNoteRow {
    pub nullifier: Vec<u8>,
    pub account_id: Vec<u8>,
    pub note_data: Vec<u8>,
    pub attempt_count: i32,
    pub last_attempt: Option<i32>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::committed_notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct CommittedNoteInsert {
    pub nullifier: Vec<u8>,
    pub account_id: Vec<u8>,
    pub note_data: Vec<u8>,
    pub attempt_count: i32,
    pub last_attempt: Option<i32>,
}

/// Row read from `inflight_notes`.
///
/// Only includes columns we need; use `.select(InflightNoteRow::as_select())` when querying.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::inflight_notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InflightNoteRow {
    pub nullifier: Vec<u8>,
    pub account_id: Vec<u8>,
    pub note_data: Vec<u8>,
    pub attempt_count: i32,
    pub last_attempt: Option<i32>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::inflight_notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InflightNoteInsert {
    pub nullifier: Vec<u8>,
    pub account_id: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub note_data: Vec<u8>,
    pub attempt_count: i32,
    pub last_attempt: Option<i32>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::inflight_nullifiers)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InflightNullifierInsert {
    pub nullifier: Vec<u8>,
    pub account_id: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub note_data: Vec<u8>,
    pub attempt_count: i32,
    pub last_attempt: Option<i32>,
}

// QUERIES
// ================================================================================================

/// Batch inserts committed notes.
pub fn insert_committed_notes(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    notes: &[SingleTargetNetworkNote],
) -> Result<(), DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);
    for note in notes {
        let row = CommittedNoteInsert {
            nullifier: conversions::nullifier_to_bytes(&note.nullifier()),
            account_id: account_id_bytes.clone(),
            note_data: conversions::single_target_note_to_bytes(note),
            attempt_count: 0,
            last_attempt: None,
        };
        diesel::replace_into(schema::committed_notes::table)
            .values(&row)
            .execute(conn)?;
    }
    Ok(())
}

/// Returns notes available for consumption by a given account.
/// (Design doc 3.2)
///
/// Returns the union of `committed_notes` + `inflight_notes` not in `inflight_nullifiers`,
/// filtered by backoff.
pub fn available_notes(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    block_num: BlockNumber,
    max_attempts: usize,
) -> Result<Vec<InflightNetworkNote>, DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);

    // Get committed notes for this account.
    let committed: Vec<CommittedNoteRow> = schema::committed_notes::table
        .filter(schema::committed_notes::account_id.eq(&account_id_bytes))
        .load(conn)?;

    // Get inflight notes for this account.
    let inflight: Vec<InflightNoteRow> = schema::inflight_notes::table
        .filter(schema::inflight_notes::account_id.eq(&account_id_bytes))
        .select(InflightNoteRow::as_select())
        .load(conn)?;

    // Get inflight nullifiers for this account (notes consumed by inflight txs).
    let nullified_set: HashSet<Vec<u8>> = schema::inflight_nullifiers::table
        .filter(schema::inflight_nullifiers::account_id.eq(&account_id_bytes))
        .select(schema::inflight_nullifiers::nullifier)
        .load(conn)?
        .into_iter()
        .collect();

    let mut result = Vec::new();

    // Process committed notes (exclude those in inflight_nullifiers).
    for row in committed {
        if nullified_set.contains(&row.nullifier) {
            continue;
        }
        let attempt_count = u32::try_from(row.attempt_count).unwrap_or(0) as usize;
        let note = note_row_to_inflight(
            &row.note_data,
            attempt_count,
            row.last_attempt.map(conversions::block_num_from_i32),
        )?;
        if note.attempt_count() < max_attempts && note.is_available(block_num) {
            result.push(note);
        }
    }

    // Process inflight notes (exclude those in inflight_nullifiers).
    for row in inflight {
        if nullified_set.contains(&row.nullifier) {
            continue;
        }
        let attempt_count = u32::try_from(row.attempt_count).unwrap_or(0) as usize;
        let note = note_row_to_inflight(
            &row.note_data,
            attempt_count,
            row.last_attempt.map(conversions::block_num_from_i32),
        )?;
        if note.attempt_count() < max_attempts && note.is_available(block_num) {
            result.push(note);
        }
    }

    Ok(result)
}

/// Marks notes as failed by updating `attempt_count` and `last_attempt`.
/// (Design doc 3.7)
pub fn notes_failed(
    conn: &mut SqliteConnection,
    nullifiers: &[Nullifier],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = conversions::block_num_to_i32(block_num);

    for nullifier in nullifiers {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);

        // Update in committed_notes.
        diesel::update(schema::committed_notes::table.find(&nullifier_bytes))
            .set((
                schema::committed_notes::attempt_count
                    .eq(schema::committed_notes::attempt_count + 1),
                schema::committed_notes::last_attempt.eq(Some(block_num_val)),
            ))
            .execute(conn)?;

        // Update in inflight_notes.
        diesel::update(schema::inflight_notes::table.find(&nullifier_bytes))
            .set((
                schema::inflight_notes::attempt_count.eq(schema::inflight_notes::attempt_count + 1),
                schema::inflight_notes::last_attempt.eq(Some(block_num_val)),
            ))
            .execute(conn)?;
    }
    Ok(())
}

/// Drops notes that have exceeded the maximum attempt count.
/// (Design doc 3.8)
pub fn drop_failing_notes(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    max_attempts: usize,
) -> Result<(), DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);
    #[allow(clippy::cast_possible_wrap)]
    let max_attempts = max_attempts as i32;

    diesel::delete(
        schema::committed_notes::table
            .filter(schema::committed_notes::account_id.eq(&account_id_bytes))
            .filter(schema::committed_notes::attempt_count.ge(max_attempts)),
    )
    .execute(conn)?;

    diesel::delete(
        schema::inflight_notes::table
            .filter(schema::inflight_notes::account_id.eq(&account_id_bytes))
            .filter(schema::inflight_notes::attempt_count.ge(max_attempts)),
    )
    .execute(conn)?;

    Ok(())
}

// HELPERS
// ================================================================================================

/// Moves consumed notes to `inflight_nullifiers` for a given transaction.
pub(super) fn insert_inflight_nullifiers(
    conn: &mut SqliteConnection,
    nullifiers: &[Nullifier],
    tx_id_bytes: &[u8],
) -> Result<(), DatabaseError> {
    for nullifier in nullifiers {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);

        // Check committed_notes first.
        let committed: Option<CommittedNoteRow> =
            schema::committed_notes::table.find(&nullifier_bytes).first(conn).optional()?;

        if let Some(note_row) = committed {
            let insert = InflightNullifierInsert {
                nullifier: nullifier_bytes.clone(),
                account_id: note_row.account_id,
                transaction_id: tx_id_bytes.to_vec(),
                note_data: note_row.note_data,
                attempt_count: note_row.attempt_count,
                last_attempt: note_row.last_attempt,
            };
            diesel::insert_into(schema::inflight_nullifiers::table)
                .values(&insert)
                .execute(conn)?;
            continue;
        }

        // Check inflight_notes.
        let inflight: Option<InflightNoteRow> = schema::inflight_notes::table
            .find(&nullifier_bytes)
            .select(InflightNoteRow::as_select())
            .first(conn)
            .optional()?;

        if let Some(note_row) = inflight {
            let insert = InflightNullifierInsert {
                nullifier: nullifier_bytes.clone(),
                account_id: note_row.account_id,
                transaction_id: tx_id_bytes.to_vec(),
                note_data: note_row.note_data,
                attempt_count: note_row.attempt_count,
                last_attempt: note_row.last_attempt,
            };
            diesel::insert_into(schema::inflight_nullifiers::table)
                .values(&insert)
                .execute(conn)?;
        }
        // Nullifiers not matching any tracked note are silently skipped. This is expected for
        // nullifiers that consume notes belonging to other accounts or external notes not tracked
        // by the ntx-builder.
    }
    Ok(())
}

/// Constructs an `InflightNetworkNote` from DB row fields.
fn note_row_to_inflight(
    note_data: &[u8],
    attempt_count: usize,
    last_attempt: Option<BlockNumber>,
) -> Result<InflightNetworkNote, DatabaseError> {
    let note = conversions::single_target_note_from_bytes(note_data)?;
    Ok(InflightNetworkNote::from_parts(note, attempt_count, last_attempt))
}
