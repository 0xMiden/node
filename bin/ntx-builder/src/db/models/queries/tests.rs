//! DB-level tests for NTX builder query functions.

use std::sync::Arc;

use diesel::prelude::*;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::PartialMmr;

use super::*;
use crate::NoteError;
use crate::committed_block::CommittedBlockEffects;
use crate::db::models::conv as conversions;
use crate::db::{Db, schema};
use crate::test_utils::*;

/// Creates a [`NoteError`] from a string message, for use in tests.
fn test_note_error(msg: &str) -> NoteError {
    Arc::new(std::io::Error::other(msg.to_string()))
}

// TEST HELPERS
// ================================================================================================

/// Creates a file-backed SQLite connection with migrations applied.
fn test_conn() -> (SqliteConnection, tempfile::TempDir) {
    Db::test_conn()
}

/// Counts the total number of rows in the `notes` table.
fn count_notes(conn: &mut SqliteConnection) -> i64 {
    schema::notes::table.count().get_result(conn).unwrap()
}

// APPLY COMMITTED BLOCK TESTS
// ================================================================================================

#[test]
fn apply_committed_block_inserts_notes_and_advances_chain_state() {
    let (conn, _dir) = &mut test_conn();

    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 10);

    let block_num = BlockNumber::from(1u32);
    let effects = CommittedBlockEffects {
        header: mock_block_header(block_num),
        network_notes: vec![note.clone()],
        nullifiers: vec![],
        network_account_updates: vec![],
    };

    let affected = apply_committed_block(conn, &effects, &PartialMmr::default()).unwrap();

    // Note inserted; note's target account is reported as affected.
    assert_eq!(count_notes(conn), 1);
    assert!(affected.contains(&account_id));

    // Chain state singleton updated.
    let stored = select_chain_state(conn).unwrap().unwrap();
    assert_eq!(stored.0, block_num);
}

#[test]
fn apply_committed_block_marks_nullifiers_consumed() {
    let (conn, _dir) = &mut test_conn();

    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 10);
    let note_id = note.as_note().id();
    let nullifier = note.as_note().nullifier();

    // First block: create note.
    let block_num1 = BlockNumber::from(1u32);
    apply_committed_block(
        conn,
        &CommittedBlockEffects {
            header: mock_block_header(block_num1),
            network_notes: vec![note.clone()],
            nullifiers: vec![],
            network_account_updates: vec![],
        },
        &PartialMmr::default(),
    )
    .unwrap();

    // Second block: consume note.
    let block_num2 = BlockNumber::from(2u32);
    let affected = apply_committed_block(
        conn,
        &CommittedBlockEffects {
            header: mock_block_header(block_num2),
            network_notes: vec![],
            nullifiers: vec![nullifier],
            network_account_updates: vec![],
        },
        &PartialMmr::default(),
    )
    .unwrap();

    // Note should be marked committed at block 2 (consumed).
    let row = get_note_status(conn, &conversions::note_id_to_bytes(&note_id))
        .unwrap()
        .unwrap();
    assert_eq!(row.committed_at, Some(conversions::block_num_to_i64(block_num2)));

    // Account whose note was consumed should be in affected list.
    assert!(affected.contains(&account_id));
}

#[test]
fn apply_committed_block_advances_chain_state() {
    let (conn, _dir) = &mut test_conn();

    let block_num1 = BlockNumber::from(1u32);
    let block_num2 = BlockNumber::from(2u32);

    apply_committed_block(
        conn,
        &CommittedBlockEffects {
            header: mock_block_header(block_num1),
            network_notes: vec![],
            nullifiers: vec![],
            network_account_updates: vec![],
        },
        &PartialMmr::default(),
    )
    .unwrap();
    apply_committed_block(
        conn,
        &CommittedBlockEffects {
            header: mock_block_header(block_num2),
            network_notes: vec![],
            nullifiers: vec![],
            network_account_updates: vec![],
        },
        &PartialMmr::default(),
    )
    .unwrap();

    let stored = select_chain_state(conn).unwrap().unwrap();
    assert_eq!(stored.0, block_num2);
}

// AVAILABLE NOTES TESTS
// ================================================================================================

#[test]
fn available_notes_filters_consumed_and_exceeded_attempts() {
    let (conn, _dir) = &mut test_conn();

    let account_id = mock_network_account_id();
    let note_good = mock_single_target_note(account_id, 10);
    let note_consumed = mock_single_target_note(account_id, 20);
    let note_failed = mock_single_target_note(account_id, 30);

    // Insert all as committed.
    insert_committed_notes(conn, &[note_good.clone(), note_consumed.clone(), note_failed.clone()])
        .unwrap();

    // Mark one as consumed by setting committed_at directly (simulates a later block).
    diesel::update(
        schema::notes::table
            .find(conversions::nullifier_to_bytes(&note_consumed.as_note().nullifier())),
    )
    .set(schema::notes::committed_at.eq(Some(1i64)))
    .execute(conn)
    .unwrap();

    // Mark one note as failed many times (exceed max_attempts=3).
    let block_num = BlockNumber::from(100u32);
    for _ in 0..3 {
        notes_failed(
            conn,
            &[(note_failed.as_note().nullifier(), test_note_error("test error"))],
            block_num,
        )
        .unwrap();
    }

    // Query available notes with max_attempts=3.
    let result = available_notes(conn, account_id, block_num, 3).unwrap();

    // Only note_good should be available.
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].as_note().nullifier(), note_good.as_note().nullifier());
}

#[test]
fn available_notes_only_returns_notes_for_specified_account() {
    let (conn, _dir) = &mut test_conn();

    let account_id_1 = mock_network_account_id();
    let account_id_2 = mock_network_account_id_seeded(42);

    let note_acct1 = mock_single_target_note(account_id_1, 10);
    let note_acct2 = mock_single_target_note(account_id_2, 20);

    insert_committed_notes(conn, &[note_acct1.clone(), note_acct2]).unwrap();

    let block_num = BlockNumber::from(100u32);
    let result = available_notes(conn, account_id_1, block_num, 30).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].as_note().nullifier(), note_acct1.as_note().nullifier());
}

// NOTES FAILED TESTS
// ================================================================================================

#[test]
fn notes_failed_increments_attempt_count() {
    let (conn, _dir) = &mut test_conn();

    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 10);

    insert_committed_notes(conn, std::slice::from_ref(&note)).unwrap();

    let block_num = BlockNumber::from(5u32);
    notes_failed(
        conn,
        &[(note.as_note().nullifier(), test_note_error("execution failed"))],
        block_num,
    )
    .unwrap();
    notes_failed(
        conn,
        &[(note.as_note().nullifier(), test_note_error("execution failed 2"))],
        block_num,
    )
    .unwrap();

    let (attempt_count, last_attempt): (i32, Option<i64>) = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note.as_note().nullifier()))
        .select((schema::notes::attempt_count, schema::notes::last_attempt))
        .first(conn)
        .unwrap();

    assert_eq!(attempt_count, 2);
    assert_eq!(last_attempt, Some(conversions::block_num_to_i64(block_num)));
}

// GET NOTE STATUS TESTS
// ================================================================================================

#[test]
fn get_note_status_returns_latest_error() {
    let (conn, _dir) = &mut test_conn();

    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 10);
    let note_id = note.as_note().id();

    // Insert as committed note.
    insert_committed_notes(conn, std::slice::from_ref(&note)).unwrap();

    // Initially no error, not consumed.
    let row = get_note_status(conn, &conversions::note_id_to_bytes(&note_id))
        .unwrap()
        .unwrap();
    assert!(row.last_error.is_none());
    assert_eq!(row.attempt_count, 0);
    assert!(row.committed_at.is_none());

    // Mark as failed.
    let block_num = BlockNumber::from(5u32);
    notes_failed(conn, &[(note.as_note().nullifier(), test_note_error("first error"))], block_num)
        .unwrap();

    let row = get_note_status(conn, &conversions::note_id_to_bytes(&note_id))
        .unwrap()
        .unwrap();
    assert_eq!(row.last_error.as_deref(), Some("first error"));
    assert_eq!(row.attempt_count, 1);

    // Mark as failed again with different error, should overwrite.
    notes_failed(
        conn,
        &[(note.as_note().nullifier(), test_note_error("second error"))],
        block_num,
    )
    .unwrap();

    let row = get_note_status(conn, &conversions::note_id_to_bytes(&note_id))
        .unwrap()
        .unwrap();
    assert_eq!(row.last_error.as_deref(), Some("second error"));
    assert_eq!(row.attempt_count, 2);
}

#[test]
fn get_note_status_returns_none_for_unknown_note() {
    let (conn, _dir) = &mut test_conn();

    let unknown_id = vec![0u8; 32];
    let result = get_note_status(conn, &unknown_id).unwrap();
    assert!(result.is_none());
}

// CHAIN STATE TESTS
// ================================================================================================

#[test]
fn upsert_chain_state_updates_singleton() {
    let (conn, _dir) = &mut test_conn();

    let block_num_1 = BlockNumber::from(1u32);
    let header_1 = mock_block_header(block_num_1);
    upsert_chain_state(conn, block_num_1, &header_1, &PartialMmr::default()).unwrap();

    // Upsert again with higher block.
    let block_num_2 = BlockNumber::from(2u32);
    let header_2 = mock_block_header(block_num_2);
    upsert_chain_state(conn, block_num_2, &header_2, &PartialMmr::default()).unwrap();

    // Should only have one row.
    let row_count: i64 = schema::chain_state::table.count().get_result(conn).unwrap();
    assert_eq!(row_count, 1);

    // Should have the latest block number.
    let stored = select_chain_state(conn).unwrap().unwrap();
    assert_eq!(stored.0, block_num_2);
}

#[test]
fn select_chain_state_returns_none_for_empty_db() {
    let (conn, _dir) = &mut test_conn();

    let result = select_chain_state(conn).unwrap();
    assert!(result.is_none());
}

// NOTE SCRIPT TESTS
// ================================================================================================

#[test]
fn note_script_insert_and_lookup() {
    let (conn, _dir) = &mut test_conn();

    // Extract a NoteScript from a mock note.
    let account_id = mock_network_account_id();
    let note: miden_protocol::note::Note = mock_single_target_note(account_id, 10).into_note();
    let script = note.script().clone();
    let root = Word::from(script.root());

    // Insert the script.
    insert_note_script(conn, &root, &script).unwrap();

    // Look it up — should match the original.
    let found = lookup_note_script(conn, &root).unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().root(), script.root());
}

#[test]
fn note_script_lookup_returns_none_for_missing() {
    let (conn, _dir) = &mut test_conn();

    let missing_root = Word::default();
    let found = lookup_note_script(conn, &missing_root).unwrap();
    assert!(found.is_none());
}

#[test]
fn note_script_insert_is_idempotent() {
    let (conn, _dir) = &mut test_conn();

    let account_id = mock_network_account_id();
    let note: miden_protocol::note::Note = mock_single_target_note(account_id, 10).into_note();
    let script = note.script().clone();
    let root = Word::from(script.root());

    // Insert the same script twice — should not error.
    insert_note_script(conn, &root, &script).unwrap();
    insert_note_script(conn, &root, &script).unwrap();

    // Should still be retrievable.
    let found = lookup_note_script(conn, &root).unwrap();
    assert!(found.is_some());
}
