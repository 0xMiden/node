//! DB-level tests for NTX builder query functions.

use diesel::prelude::*;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountStorageMode, AccountType};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteExecutionHint;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE,
    AccountIdBuilder,
};
use miden_protocol::transaction::TransactionId;
use miden_standards::note::NetworkAccountTarget;
use miden_standards::testing::note::NoteBuilder;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use super::*;
use crate::db::models::conv as conversions;
use crate::db::{Db, schema};

// TEST HELPERS
// ================================================================================================

/// Creates an in-memory SQLite connection with migrations applied.
fn test_conn() -> SqliteConnection {
    Db::test_conn()
}

/// Creates a network account ID from a test constant.
fn mock_network_account_id() -> NetworkAccountId {
    let account_id: AccountId =
        ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
    NetworkAccountId::try_from(account_id).unwrap()
}

/// Creates a distinct network account ID using a seeded RNG.
fn mock_network_account_id_seeded(seed: u8) -> NetworkAccountId {
    let account_id = AccountIdBuilder::new()
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Network)
        .build_with_seed([seed; 32]);
    NetworkAccountId::try_from(account_id).unwrap()
}

/// Creates a unique `TransactionId` from a seed value.
fn mock_tx_id(seed: u64) -> TransactionId {
    let w = |n: u64| Word::try_from([n, 0, 0, 0]).unwrap();
    TransactionId::new(w(seed), w(seed + 1), w(seed + 2), w(seed + 3))
}

/// Creates a `SingleTargetNetworkNote` targeting the given network account.
fn mock_single_target_note(
    network_account_id: NetworkAccountId,
    seed: u8,
) -> SingleTargetNetworkNote {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sender = AccountIdBuilder::new()
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Private)
        .build_with_rng(&mut rng);

    let target = NetworkAccountTarget::new(network_account_id.inner(), NoteExecutionHint::Always)
        .expect("network account should be valid target");

    let note = NoteBuilder::new(sender, rng).attachment(target).build().unwrap();

    SingleTargetNetworkNote::try_from(note).expect("note should be single-target network note")
}

/// Counts the total number of rows in the `notes` table.
fn count_notes(conn: &mut SqliteConnection) -> i64 {
    schema::notes::table.count().get_result(conn).unwrap()
}

/// Counts the total number of rows in the `accounts` table.
fn count_accounts(conn: &mut SqliteConnection) -> i64 {
    schema::accounts::table.count().get_result(conn).unwrap()
}

/// Counts inflight account rows.
fn count_inflight_accounts(conn: &mut SqliteConnection) -> i64 {
    schema::accounts::table
        .filter(schema::accounts::transaction_id.is_not_null())
        .count()
        .get_result(conn)
        .unwrap()
}

/// Counts committed account rows.
fn count_committed_accounts(conn: &mut SqliteConnection) -> i64 {
    schema::accounts::table
        .filter(schema::accounts::transaction_id.is_null())
        .count()
        .get_result(conn)
        .unwrap()
}

// PURGE INFLIGHT TESTS
// ================================================================================================

#[test]
fn purge_inflight_clears_all_inflight_state() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let tx_id = mock_tx_id(1);
    let note = mock_single_target_note(account_id, 10);

    // Insert committed account.
    upsert_committed_account(conn, account_id, &mock_account(account_id)).unwrap();

    // Insert a transaction (creates inflight account row + note + consumption).
    handle_transaction_added(conn, &tx_id, None, std::slice::from_ref(&note), &[]).unwrap();

    assert!(count_inflight_accounts(conn) == 0); // No account delta, so no inflight account.
    assert_eq!(count_notes(conn), 1);

    // Mark note as consumed by another tx.
    let tx_id2 = mock_tx_id(2);
    handle_transaction_added(conn, &tx_id2, None, &[], &[note.nullifier()]).unwrap();

    // Verify consumed_by is set.
    let consumed_count: i64 = schema::notes::table
        .filter(schema::notes::consumed_by.is_not_null())
        .count()
        .get_result(conn)
        .unwrap();
    assert_eq!(consumed_count, 1);

    // Purge inflight state.
    purge_inflight(conn).unwrap();

    // Inflight accounts should be gone.
    assert_eq!(count_inflight_accounts(conn), 0);
    // Committed account should remain.
    assert_eq!(count_committed_accounts(conn), 1);
    // Inflight-created notes should be gone.
    assert_eq!(count_notes(conn), 0);
}

// HANDLE TRANSACTION ADDED TESTS
// ================================================================================================

#[test]
fn transaction_added_inserts_notes_and_marks_consumed() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let tx_id = mock_tx_id(1);
    let note1 = mock_single_target_note(account_id, 10);
    let note2 = mock_single_target_note(account_id, 20);

    // Insert committed note first (to test consumption).
    insert_committed_notes(conn, std::slice::from_ref(&note1)).unwrap();
    assert_eq!(count_notes(conn), 1);

    // Add transaction that creates note2 and consumes note1.
    handle_transaction_added(
        conn,
        &tx_id,
        None,
        std::slice::from_ref(&note2),
        &[note1.nullifier()],
    )
    .unwrap();

    // Should now have 2 notes total.
    assert_eq!(count_notes(conn), 2);

    // note1 should be consumed.
    let consumed: Option<Vec<u8>> = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note1.nullifier()))
        .select(schema::notes::consumed_by)
        .first(conn)
        .unwrap();
    assert!(consumed.is_some());

    // note2 should have created_by set.
    let created: Option<Vec<u8>> = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note2.nullifier()))
        .select(schema::notes::created_by)
        .first(conn)
        .unwrap();
    assert!(created.is_some());
}

#[test]
fn transaction_added_is_idempotent_for_notes() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let tx_id = mock_tx_id(1);
    let note = mock_single_target_note(account_id, 10);

    // Insert the same transaction twice.
    handle_transaction_added(conn, &tx_id, None, std::slice::from_ref(&note), &[]).unwrap();
    handle_transaction_added(conn, &tx_id, None, std::slice::from_ref(&note), &[]).unwrap();

    // Should only have one note (INSERT OR IGNORE).
    assert_eq!(count_notes(conn), 1);
}

// HANDLE BLOCK COMMITTED TESTS
// ================================================================================================

#[test]
fn block_committed_promotes_inflight_notes_to_committed() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let tx_id = mock_tx_id(1);
    let note = mock_single_target_note(account_id, 10);
    let block_num = BlockNumber::from(1u32);
    let header = mock_block_header(block_num);

    // Add a transaction that creates a note.
    handle_transaction_added(conn, &tx_id, None, std::slice::from_ref(&note), &[]).unwrap();

    // Verify created_by is set.
    let created: Option<Vec<u8>> = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note.nullifier()))
        .select(schema::notes::created_by)
        .first(conn)
        .unwrap();
    assert!(created.is_some());

    // Commit the block.
    handle_block_committed(conn, &[tx_id], block_num, &header).unwrap();

    // created_by should now be NULL (promoted to committed).
    let created: Option<Vec<u8>> = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note.nullifier()))
        .select(schema::notes::created_by)
        .first(conn)
        .unwrap();
    assert!(created.is_none());
}

#[test]
fn block_committed_deletes_consumed_notes() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 10);

    // Insert a committed note.
    insert_committed_notes(conn, std::slice::from_ref(&note)).unwrap();
    assert_eq!(count_notes(conn), 1);

    // Consume it via a transaction.
    let tx_id = mock_tx_id(1);
    handle_transaction_added(conn, &tx_id, None, &[], &[note.nullifier()]).unwrap();

    // Commit the block.
    let block_num = BlockNumber::from(1u32);
    let header = mock_block_header(block_num);
    handle_block_committed(conn, &[tx_id], block_num, &header).unwrap();

    // Consumed note should be deleted.
    assert_eq!(count_notes(conn), 0);
}

#[test]
fn block_committed_promotes_inflight_account_to_committed() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let account = mock_account(account_id);

    // Insert committed account.
    upsert_committed_account(conn, account_id, &account).unwrap();
    assert_eq!(count_committed_accounts(conn), 1);

    // Insert inflight row.
    let tx_id = mock_tx_id(1);
    let row = AccountInsert {
        account_id: conversions::network_account_id_to_bytes(account_id),
        transaction_id: Some(conversions::transaction_id_to_bytes(&tx_id)),
        account_data: conversions::account_to_bytes(&account),
    };
    diesel::insert_into(schema::accounts::table).values(&row).execute(conn).unwrap();

    assert_eq!(count_inflight_accounts(conn), 1);
    assert_eq!(count_committed_accounts(conn), 1);

    // Commit the block.
    let block_num = BlockNumber::from(1u32);
    let header = mock_block_header(block_num);
    handle_block_committed(conn, &[tx_id], block_num, &header).unwrap();

    // Should have 1 committed and 0 inflight.
    assert_eq!(count_committed_accounts(conn), 1);
    assert_eq!(count_inflight_accounts(conn), 0);
}

// HANDLE TRANSACTIONS REVERTED TESTS
// ================================================================================================

#[test]
fn transactions_reverted_restores_consumed_notes() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 10);

    // Insert committed note.
    insert_committed_notes(conn, std::slice::from_ref(&note)).unwrap();

    // Consume it via a transaction.
    let tx_id = mock_tx_id(1);
    handle_transaction_added(conn, &tx_id, None, &[], &[note.nullifier()]).unwrap();

    // Verify consumed.
    let consumed: Option<Vec<u8>> = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note.nullifier()))
        .select(schema::notes::consumed_by)
        .first(conn)
        .unwrap();
    assert!(consumed.is_some());

    // Revert the transaction.
    let reverted = handle_transactions_reverted(conn, &[tx_id]).unwrap();
    assert!(reverted.is_empty());

    // Note should be un-consumed.
    let consumed: Option<Vec<u8>> = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note.nullifier()))
        .select(schema::notes::consumed_by)
        .first(conn)
        .unwrap();
    assert!(consumed.is_none());
}

#[test]
fn transactions_reverted_deletes_inflight_created_notes() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let tx_id = mock_tx_id(1);
    let note = mock_single_target_note(account_id, 10);

    // Add transaction that creates a note.
    handle_transaction_added(conn, &tx_id, None, std::slice::from_ref(&note), &[]).unwrap();
    assert_eq!(count_notes(conn), 1);

    // Revert the transaction.
    handle_transactions_reverted(conn, &[tx_id]).unwrap();

    // Inflight-created note should be deleted.
    assert_eq!(count_notes(conn), 0);
}

#[test]
fn transactions_reverted_reports_reverted_account_creations() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let account = mock_account(account_id);
    let tx_id = mock_tx_id(1);

    // Insert an inflight account row (simulating account creation by tx).
    let row = AccountInsert {
        account_id: conversions::network_account_id_to_bytes(account_id),
        transaction_id: Some(conversions::transaction_id_to_bytes(&tx_id)),
        account_data: conversions::account_to_bytes(&account),
    };
    diesel::insert_into(schema::accounts::table).values(&row).execute(conn).unwrap();

    // Revert the transaction --- account creation should be reported.
    let reverted = handle_transactions_reverted(conn, &[tx_id]).unwrap();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0], account_id);

    // Account should be gone.
    assert_eq!(count_accounts(conn), 0);
}

// AVAILABLE NOTES TESTS
// ================================================================================================

#[test]
#[allow(clippy::similar_names)]
fn available_notes_filters_consumed_and_exceeded_attempts() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let note_good = mock_single_target_note(account_id, 10);
    let note_consumed = mock_single_target_note(account_id, 20);
    let note_failed = mock_single_target_note(account_id, 30);

    // Insert all as committed.
    insert_committed_notes(conn, &[note_good.clone(), note_consumed.clone(), note_failed.clone()])
        .unwrap();

    // Consume one note.
    let tx_id = mock_tx_id(1);
    handle_transaction_added(conn, &tx_id, None, &[], &[note_consumed.nullifier()]).unwrap();

    // Mark one note as failed many times (exceed max_attempts=3).
    let block_num = BlockNumber::from(100u32);
    notes_failed(conn, &[note_failed.nullifier()], block_num).unwrap();
    notes_failed(conn, &[note_failed.nullifier()], block_num).unwrap();
    notes_failed(conn, &[note_failed.nullifier()], block_num).unwrap();

    // Query available notes with max_attempts=3.
    let result = available_notes(conn, account_id, block_num, 3).unwrap();

    // Only note_good should be available (note_consumed is consumed, note_failed exceeded
    // attempts).
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].to_inner().nullifier(), note_good.nullifier());
}

#[test]
fn available_notes_only_returns_notes_for_specified_account() {
    let conn = &mut test_conn();

    let account_id_1 = mock_network_account_id();
    let account_id_2 = mock_network_account_id_seeded(42);

    let note_acct1 = mock_single_target_note(account_id_1, 10);
    let note_acct2 = mock_single_target_note(account_id_2, 20);

    insert_committed_notes(conn, &[note_acct1.clone(), note_acct2]).unwrap();

    let block_num = BlockNumber::from(100u32);
    let result = available_notes(conn, account_id_1, block_num, 30).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].to_inner().nullifier(), note_acct1.nullifier());
}

// DROP FAILING NOTES TESTS
// ================================================================================================

#[test]
fn drop_failing_notes_scoped_to_account() {
    let conn = &mut test_conn();

    let account_id_1 = mock_network_account_id();
    let account_id_2 = mock_network_account_id_seeded(42);

    let note_acct1 = mock_single_target_note(account_id_1, 10);
    let note_acct2 = mock_single_target_note(account_id_2, 20);

    // Insert both as committed.
    insert_committed_notes(conn, &[note_acct1.clone(), note_acct2.clone()]).unwrap();

    // Fail both notes enough times to exceed max_attempts=2.
    let block_num = BlockNumber::from(100u32);
    notes_failed(conn, &[note_acct1.nullifier()], block_num).unwrap();
    notes_failed(conn, &[note_acct1.nullifier()], block_num).unwrap();
    notes_failed(conn, &[note_acct2.nullifier()], block_num).unwrap();
    notes_failed(conn, &[note_acct2.nullifier()], block_num).unwrap();

    // Drop failing notes for account_id_1 only.
    drop_failing_notes(conn, account_id_1, 2).unwrap();

    // note_acct1 should be deleted, note_acct2 should remain.
    assert_eq!(count_notes(conn), 1);
    let remaining: Vec<Vec<u8>> =
        schema::notes::table.select(schema::notes::nullifier).load(conn).unwrap();
    assert_eq!(remaining[0], conversions::nullifier_to_bytes(&note_acct2.nullifier()));
}

// NOTES FAILED TESTS
// ================================================================================================

#[test]
fn notes_failed_increments_attempt_count() {
    let conn = &mut test_conn();

    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 10);

    insert_committed_notes(conn, std::slice::from_ref(&note)).unwrap();

    let block_num = BlockNumber::from(5u32);
    notes_failed(conn, &[note.nullifier()], block_num).unwrap();
    notes_failed(conn, &[note.nullifier()], block_num).unwrap();

    let (attempt_count, last_attempt): (i32, Option<i64>) = schema::notes::table
        .find(conversions::nullifier_to_bytes(&note.nullifier()))
        .select((schema::notes::attempt_count, schema::notes::last_attempt))
        .first(conn)
        .unwrap();

    assert_eq!(attempt_count, 2);
    assert_eq!(last_attempt, Some(conversions::block_num_to_i64(block_num)));
}

// CHAIN STATE TESTS
// ================================================================================================

#[test]
fn upsert_chain_state_updates_singleton() {
    let conn = &mut test_conn();

    let block_num_1 = BlockNumber::from(1u32);
    let header_1 = mock_block_header(block_num_1);
    upsert_chain_state(conn, block_num_1, &header_1).unwrap();

    // Upsert again with higher block.
    let block_num_2 = BlockNumber::from(2u32);
    let header_2 = mock_block_header(block_num_2);
    upsert_chain_state(conn, block_num_2, &header_2).unwrap();

    // Should only have one row.
    let row_count: i64 = schema::chain_state::table.count().get_result(conn).unwrap();
    assert_eq!(row_count, 1);

    // Should have the latest block number.
    let stored_block_num: i64 = schema::chain_state::table
        .select(schema::chain_state::block_num)
        .first(conn)
        .unwrap();
    assert_eq!(stored_block_num, conversions::block_num_to_i64(block_num_2));
}

// HELPERS (domain type construction)
// ================================================================================================

/// Creates a mock `Account` for a network account.
///
/// Uses `AccountBuilder` with minimal components needed for serialization.
fn mock_account(_account_id: NetworkAccountId) -> miden_protocol::account::Account {
    use miden_protocol::account::auth::PublicKeyCommitment;
    use miden_protocol::account::{AccountBuilder, AccountComponent};
    use miden_standards::account::auth::AuthFalcon512Rpo;

    let component_code = miden_standards::code_builder::CodeBuilder::default()
        .compile_component_code("test::interface", "pub proc test_proc push.1.2 add end")
        .unwrap();

    let component =
        AccountComponent::new(component_code, vec![]).unwrap().with_supports_all_types();

    AccountBuilder::new([0u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Network)
        .with_component(component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(Word::default())))
        .build_existing()
        .unwrap()
}

/// Creates a mock `BlockHeader` for the given block number.
fn mock_block_header(block_num: BlockNumber) -> miden_protocol::block::BlockHeader {
    miden_protocol::block::BlockHeader::mock(block_num, None, None, &[], Word::default())
}
