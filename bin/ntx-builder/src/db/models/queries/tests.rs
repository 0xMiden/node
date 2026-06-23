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

    upsert_account(conn, account_id, &account, mock_transaction_id(1)).unwrap();
    upsert_account(conn, account_id, &account, mock_transaction_id(2)).unwrap();

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

    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();
    // Re-applying the same block (e.g. on a subscription redelivery) must not error or duplicate.
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();

    assert_eq!(count_notes(conn), 1);
}

#[test]
fn mark_notes_consumed_keeps_rows_and_sets_committed_at() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note_a = mock_single_target_note(account_id, 1);
    let note_b = mock_single_target_note(account_id, 2);

    insert_network_notes(conn, &[note_a.clone(), note_b.clone()], BlockNumber::from(1u32)).unwrap();
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
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();

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
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();

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
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();

    let available = available_notes(conn, account_id, BlockNumber::from(1), 30).unwrap();
    assert_eq!(available.len(), 1);
}

#[test]
fn available_notes_excludes_attempts_at_cap() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 13);
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();

    // Push attempt_count up to the cap.
    let nullifier = note.as_note().nullifier();
    for _ in 0..30 {
        notes_failed(conn, &[(nullifier, test_note_error("boom"))], BlockNumber::from(5)).unwrap();
    }

    let available = available_notes(conn, account_id, BlockNumber::from(1000), 30).unwrap();
    assert!(available.is_empty(), "notes at the attempt cap should not be available");
}

// PENDING NOTE EXPIRY
// ================================================================================================

#[test]
fn delete_expired_pending_notes_removes_old_keeps_recent() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();

    // An old note (received long ago) and a recent one for the same account.
    let old_note = mock_single_target_note(account_id, 1);
    let recent_note = mock_single_target_note(account_id, 2);
    insert_network_notes(conn, std::slice::from_ref(&old_note), BlockNumber::from(1u32)).unwrap();
    insert_network_notes(conn, std::slice::from_ref(&recent_note), BlockNumber::from(100u32))
        .unwrap();
    assert_eq!(count_notes(conn), 2);

    // Tip 100, retention 50 → cutoff block 50. Only the note received at block 1 is older.
    let deleted = delete_expired_pending_notes(conn, BlockNumber::from(100u32), 50).unwrap();
    assert_eq!(deleted, 1);

    assert!(
        get_note_status(conn, &crate::db::models::conv::note_id_to_bytes(&old_note.as_note().id()))
            .unwrap()
            .is_none(),
        "the stale pending note should be deleted",
    );
    assert!(
        get_note_status(
            conn,
            &crate::db::models::conv::note_id_to_bytes(&recent_note.as_note().id())
        )
        .unwrap()
        .is_some(),
        "the recent pending note should be retained",
    );
}

#[test]
fn delete_expired_pending_notes_keeps_consumed_notes() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();

    // An old note that has since been consumed must be retained for status reporting even though it
    // is well past the retention window.
    let note = mock_single_target_note(account_id, 1);
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();
    mark_notes_consumed(conn, &[note.as_note().nullifier()], BlockNumber::from(5)).unwrap();

    let deleted = delete_expired_pending_notes(conn, BlockNumber::from(1000u32), 10).unwrap();
    assert_eq!(deleted, 0, "consumed notes are exempt from age expiry");
    assert_eq!(count_notes(conn), 1);
}

#[test]
fn delete_expired_pending_notes_is_noop_before_window_elapses() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 1);
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();

    // Tip below the retention window: cutoff saturates to 0, so nothing is old enough yet.
    let deleted = delete_expired_pending_notes(conn, BlockNumber::from(5u32), 50).unwrap();
    assert_eq!(deleted, 0);
    assert_eq!(count_notes(conn), 1);
}

// CHAIN STATE
// ================================================================================================

#[test]
fn update_chain_state_tip_persists_and_roundtrips_mmr() {
    let (conn, _dir) = &mut test_conn();
    let genesis = mock_block_header(BlockNumber::GENESIS);
    let header = mock_block_header(BlockNumber::from(7));
    let mmr = PartialMmr::default();

    insert_genesis_chain_state(conn, &genesis, &genesis.commitment()).unwrap();
    update_chain_state_tip(conn, header.block_num(), &header, &mmr).unwrap();

    let (loaded_num, loaded_header, _loaded_mmr) = select_chain_state(conn).unwrap().unwrap();
    assert_eq!(loaded_num, header.block_num());
    assert_eq!(loaded_header.block_num(), header.block_num());
}

#[test]
fn update_chain_state_tip_keeps_singleton() {
    let (conn, _dir) = &mut test_conn();
    let genesis = mock_block_header(BlockNumber::GENESIS);
    let header_1 = mock_block_header(BlockNumber::from(1));
    let header_2 = mock_block_header(BlockNumber::from(2));
    let mmr = PartialMmr::default();

    insert_genesis_chain_state(conn, &genesis, &genesis.commitment()).unwrap();
    update_chain_state_tip(conn, header_1.block_num(), &header_1, &mmr).unwrap();
    update_chain_state_tip(conn, header_2.block_num(), &header_2, &mmr).unwrap();

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

// ACCOUNTS WITH PENDING NOTES
// ================================================================================================

#[test]
fn accounts_with_pending_notes_distinct_and_filters_consumed_and_capped() {
    let (conn, _dir) = &mut test_conn();
    let alice = mock_network_account_id();
    let bob = mock_network_account_id_seeded(42);
    let carol = mock_network_account_id_seeded(99);

    let alice_note_1 = mock_single_target_note(alice, 1);
    let alice_note_2 = mock_single_target_note(alice, 2);
    let bob_note = mock_single_target_note(bob, 3);
    let carol_note = mock_single_target_note(carol, 4);

    insert_network_notes(
        conn,
        &[alice_note_1.clone(), alice_note_2, bob_note.clone(), carol_note.clone()],
        BlockNumber::from(1u32),
    )
    .unwrap();

    // Alice has two notes — must still appear exactly once (DISTINCT). Bob's only note is already
    // consumed — exclude.
    mark_notes_consumed(conn, &[bob_note.as_note().nullifier()], BlockNumber::from(7)).unwrap();
    // Carol's note has hit the attempt cap — exclude.
    for _ in 0..30 {
        notes_failed(
            conn,
            &[(carol_note.as_note().nullifier(), test_note_error("boom"))],
            BlockNumber::from(5),
        )
        .unwrap();
    }

    let pending = accounts_with_pending_notes(conn, 30).unwrap();
    assert_eq!(pending.len(), 1, "only alice should remain pending");
    assert_eq!(pending[0], alice);
}

// SUBMITTED-TX LANDING
// ================================================================================================

#[test]
fn account_last_tx_roundtrips_and_updates() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let account = mock_account(account_id);

    // The first upsert records its transaction id; a later upsert overwrites it.
    let first = mock_transaction_id(1);
    let second = mock_transaction_id(2);
    upsert_account(conn, account_id, &account, first).unwrap();
    assert_eq!(account_last_tx(conn, account_id).unwrap(), Some(first));
    upsert_account(conn, account_id, &account, second).unwrap();
    assert_eq!(account_last_tx(conn, account_id).unwrap(), Some(second));
}

#[test]
fn account_last_tx_returns_none_for_untracked_account() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();

    // No row exists for this account.
    assert_eq!(account_last_tx(conn, account_id).unwrap(), None);
}

// GENESIS APPLICATION
// ================================================================================================

/// Builds genesis-shaped effects: a full-state network-account update with no originating
/// transactions, at [`BlockNumber::GENESIS`].
fn genesis_effects() -> CommittedBlockEffects {
    let (account, details) = mock_network_account_update();
    CommittedBlockEffects {
        header: mock_block_header(BlockNumber::GENESIS),
        network_notes: vec![],
        nullifiers: vec![],
        network_account_updates: vec![(account.id(), details)],
        account_transactions: vec![],
    }
}

#[test]
fn apply_committed_block_seeds_genesis_network_account() {
    let (conn, _dir) = &mut test_conn();
    let effects = genesis_effects();
    let account_id = effects.network_account_updates[0].0;

    // Genesis has no transactions, so this used to panic on the "must originate from a transaction"
    // invariant. It must now bootstrap the account successfully.
    apply_committed_block(conn, &effects, &PartialMmr::default()).unwrap();

    assert!(
        get_account(conn, account_id).unwrap().is_some(),
        "genesis account should be seeded"
    );
    // The seeded account carries the zero sentinel: no transaction produced it. An actor never
    // submits the zero id, so this can never be mistaken for a landed transaction.
    assert_eq!(
        account_last_tx(conn, account_id).unwrap(),
        Some(TransactionId::from_raw(Word::empty())),
    );
}

#[test]
#[should_panic(expected = "must originate from a transaction")]
fn apply_committed_block_panics_on_txless_update_after_genesis() {
    let (conn, _dir) = &mut test_conn();
    // Same shape as genesis but at a non-genesis height: a committed account update with no
    // originating transaction is a real block-producer invariant violation and must still panic.
    let mut effects = genesis_effects();
    effects.header = mock_block_header(BlockNumber::from(1));

    apply_committed_block(conn, &effects, &PartialMmr::default()).unwrap();
}

#[test]
fn notes_failed_increments_attempt_and_records_error() {
    let (conn, _dir) = &mut test_conn();
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 19);
    insert_network_notes(conn, std::slice::from_ref(&note), BlockNumber::from(1u32)).unwrap();

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
