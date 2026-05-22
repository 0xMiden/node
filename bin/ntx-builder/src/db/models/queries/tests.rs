//! DB-level tests for the committed-block-driven query layer.

use std::sync::Arc;

use diesel::prelude::*;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::PartialMmr;

use super::*;
use crate::NoteError;
use crate::db::{Db, schema};
use crate::test_utils::*;

/// Creates a [`NoteError`] from a string message, for use in tests.
fn test_note_error(msg: &str) -> NoteError {
    Arc::new(std::io::Error::other(msg.to_string()))
}

/// Creates a file-backed SQLite connection with migrations applied.
fn test_conn() -> (SqliteConnection, tempfile::TempDir) {
    Db::test_conn()
}

/// Counts the total number of rows in the `notes` table.
fn count_notes(conn: &mut SqliteConnection) -> i64 {
    schema::notes::table.count().get_result(conn).unwrap()
}

/// Counts the total number of rows in the `accounts` table.
fn count_accounts(conn: &mut SqliteConnection) -> i64 {
    schema::accounts::table.count().get_result(conn).unwrap()
}

// ACCOUNT UPSERT
// ================================================================================================

#[test]
fn upsert_account_replaces_existing_row() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let account = mock_account(account_id);

    upsert_account(conn, account_id, &account).unwrap();
    upsert_account(conn, account_id, &account).unwrap();

    assert_eq!(count_accounts(conn), 1, "second upsert must overwrite, not insert");
    assert!(get_account(conn, account_id).unwrap().is_some());
}

// NETWORK NOTE INSERT/DELETE
// ================================================================================================

#[test]
fn insert_network_notes_is_idempotent() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 7);

    insert_network_notes(conn, std::slice::from_ref(&note)).unwrap();
    // Re-applying the same block (e.g. on a subscription redelivery) must not error or duplicate.
    insert_network_notes(conn, std::slice::from_ref(&note)).unwrap();

    assert_eq!(count_notes(conn), 1);
}

#[test]
fn mark_notes_consumed_keeps_rows_and_sets_committed_at() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note_a = mock_single_target_note(account_id, 1);
    let note_b = mock_single_target_note(account_id, 2);

    insert_network_notes(conn, &[note_a.clone(), note_b.clone()]).unwrap();
    assert_eq!(count_notes(conn), 2);

    let consumed_at = BlockNumber::from(42);
    mark_notes_consumed(conn, &[note_a.as_note().nullifier()], consumed_at).unwrap();

    // Both rows are still present so the gRPC status endpoint can report them.
    assert_eq!(count_notes(conn), 2);

    let status_a =
        get_note_status(conn, &crate::db::models::conv::note_id_to_bytes(&note_a.as_note().id()))
            .unwrap()
            .unwrap();
    assert_eq!(status_a.committed_at, Some(i64::from(consumed_at.as_u32())));

    let status_b =
        get_note_status(conn, &crate::db::models::conv::note_id_to_bytes(&note_b.as_note().id()))
            .unwrap()
            .unwrap();
    assert!(status_b.committed_at.is_none());
}

#[test]
fn mark_notes_consumed_is_noop_when_unknown() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 3);
    insert_network_notes(conn, std::slice::from_ref(&note)).unwrap();

    // A nullifier we never inserted should not affect existing rows.
    let phantom = mock_single_target_note(account_id, 99).as_note().nullifier();
    mark_notes_consumed(conn, &[phantom], BlockNumber::from(5)).unwrap();

    assert_eq!(count_notes(conn), 1);
    let status =
        get_note_status(conn, &crate::db::models::conv::note_id_to_bytes(&note.as_note().id()))
            .unwrap()
            .unwrap();
    assert!(status.committed_at.is_none());
}

#[test]
fn available_notes_excludes_consumed_notes() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 21);
    insert_network_notes(conn, std::slice::from_ref(&note)).unwrap();

    assert_eq!(available_notes(conn, account_id, BlockNumber::from(1), 30).unwrap().len(), 1);

    mark_notes_consumed(conn, &[note.as_note().nullifier()], BlockNumber::from(7)).unwrap();

    assert!(
        available_notes(conn, account_id, BlockNumber::from(1000), 30)
            .unwrap()
            .is_empty()
    );
}

// AVAILABLE NOTES + BACKOFF
// ================================================================================================

#[test]
fn available_notes_returns_unconsumed_under_attempt_cap() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 11);
    insert_network_notes(conn, std::slice::from_ref(&note)).unwrap();

    let available = available_notes(conn, account_id, BlockNumber::from(1), 30).unwrap();
    assert_eq!(available.len(), 1);
}

#[test]
fn available_notes_excludes_attempts_at_cap() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 13);
    insert_network_notes(conn, std::slice::from_ref(&note)).unwrap();

    // Push attempt_count up to the cap.
    let nullifier = note.as_note().nullifier();
    for _ in 0..30 {
        notes_failed(conn, &[(nullifier, test_note_error("boom"))], BlockNumber::from(5)).unwrap();
    }

    let available = available_notes(conn, account_id, BlockNumber::from(1000), 30).unwrap();
    assert!(available.is_empty(), "notes at the attempt cap should not be available");
}

// CHAIN STATE
// ================================================================================================

#[test]
fn upsert_chain_state_persists_and_roundtrips_mmr() {
    let (conn, _dir) = &mut test_conn();
    let header = mock_block_header(BlockNumber::from(7));
    let mmr = PartialMmr::default();

    upsert_chain_state(conn, header.block_num(), &header, &mmr).unwrap();

    let (loaded_num, loaded_header, _loaded_mmr) = select_chain_state(conn).unwrap().unwrap();
    assert_eq!(loaded_num, header.block_num());
    assert_eq!(loaded_header.block_num(), header.block_num());
}

#[test]
fn upsert_chain_state_overwrites_singleton() {
    let (conn, _dir) = &mut test_conn();
    let header_1 = mock_block_header(BlockNumber::from(1));
    let header_2 = mock_block_header(BlockNumber::from(2));
    let mmr = PartialMmr::default();

    upsert_chain_state(conn, header_1.block_num(), &header_1, &mmr).unwrap();
    upsert_chain_state(conn, header_2.block_num(), &header_2, &mmr).unwrap();

    let (loaded_num, ..) = select_chain_state(conn).unwrap().unwrap();
    assert_eq!(loaded_num, header_2.block_num());

    let row_count: i64 = schema::chain_state::table.count().get_result(conn).unwrap();
    assert_eq!(row_count, 1, "chain_state must remain a singleton");
}

#[test]
fn select_chain_state_returns_none_on_fresh_db() {
    let (conn, _dir) = &mut test_conn();
    assert!(select_chain_state(conn).unwrap().is_none());
}

// NOTE SCRIPT CACHE
// ================================================================================================

#[test]
fn note_script_cache_roundtrip() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 17);
    let script = note.as_note().script().clone();
    let root: Word = script.root().into();

    assert!(lookup_note_script(conn, &root).unwrap().is_none());
    insert_note_script(conn, &root, &script).unwrap();
    assert!(lookup_note_script(conn, &root).unwrap().is_some());

    // Re-insert is idempotent.
    insert_note_script(conn, &root, &script).unwrap();
}

// NOTE STATUS
// ================================================================================================

#[test]
fn notes_failed_increments_attempt_and_records_error() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 19);
    insert_network_notes(conn, std::slice::from_ref(&note)).unwrap();

    let nullifier = note.as_note().nullifier();
    notes_failed(conn, &[(nullifier, test_note_error("nope"))], BlockNumber::from(5)).unwrap();
    notes_failed(conn, &[(nullifier, test_note_error("nope"))], BlockNumber::from(6)).unwrap();

    let row =
        get_note_status(conn, &crate::db::models::conv::note_id_to_bytes(&note.as_note().id()))
            .unwrap()
            .unwrap();
    assert_eq!(row.attempt_count, 2);
    assert_eq!(row.last_attempt, Some(6));
    assert!(row.last_error.is_some());
}
