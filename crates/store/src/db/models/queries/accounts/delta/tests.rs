//!
//! Tests for delta update functionality.

use std::collections::BTreeMap;

use assert_matches::assert_matches;
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use diesel_migrations::MigrationHarness;
use miden_node_utils::fee::test_fee_params;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::delta::{
    AccountStorageDelta,
    AccountUpdateDetails,
    AccountVaultDelta,
    StorageMapDelta,
    StorageSlotDelta,
};
use miden_protocol::account::{
    AccountBuilder,
    AccountComponent,
    AccountDelta,
    AccountId,
    AccountStorageMode,
    AccountType,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::{BlockAccountUpdate, BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::utils::Serializable;
use miden_protocol::{EMPTY_WORD, Felt, Word};
use miden_standards::account::auth::AuthFalcon512Rpo;
use miden_standards::code_builder::CodeBuilder;

use crate::db::migrations::MIGRATIONS;
use crate::db::models::queries::accounts::{
    select_account_header_with_storage_header_at_block,
    select_account_vault_at_block,
    select_full_account,
    upsert_accounts,
};
use crate::db::schema::accounts;

fn setup_test_db() -> SqliteConnection {
    let mut conn =
        SqliteConnection::establish(":memory:").expect("Failed to create in-memory database");

    conn.run_pending_migrations(MIGRATIONS).expect("Failed to run migrations");

    conn
}

fn insert_block_header(conn: &mut SqliteConnection, block_num: BlockNumber) {
    use crate::db::schema::block_headers;

    let secret_key = SecretKey::new();
    let block_header = BlockHeader::new(
        1_u8.into(),
        Word::default(),
        block_num,
        Word::default(),
        Word::default(),
        Word::default(),
        Word::default(),
        Word::default(),
        Word::default(),
        secret_key.public_key(),
        test_fee_params(),
        0_u8.into(),
    );
    let signature = secret_key.sign(block_header.commitment());

    diesel::insert_into(block_headers::table)
        .values((
            block_headers::block_num.eq(i64::from(block_num.as_u32())),
            block_headers::block_header.eq(block_header.to_bytes()),
            block_headers::signature.eq(signature.to_bytes()),
            block_headers::commitment.eq(block_header.commitment().to_bytes()),
        ))
        .execute(conn)
        .expect("Failed to insert block header");
}

/// Tests that the optimized delta update path produces the same results as the old
/// method that loads the full account.
///
/// Covers partial deltas that update:
/// - Nonce (via `nonce_delta`)
/// - Value storage slots
/// - Vault assets (fungible) starting from empty vault
///
/// The test ensures the optimized code path in `upsert_accounts` produces correct results
/// by comparing the final account state against a manually constructed expected state.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "test exercises multiple storage and vault paths"
)]
fn optimized_delta_matches_full_account_method() {
    // Use deterministic account seed to keep account IDs stable.
    const ACCOUNT_SEED: [u8; 32] = [10u8; 32];
    // Use fixed block numbers to ensure deterministic ordering.
    const BLOCK_NUM_1: u32 = 1;
    const BLOCK_NUM_2: u32 = 2;
    // Use explicit slot indices to avoid magic numbers.
    const SLOT_INDEX_PRIMARY: usize = 0;
    const SLOT_INDEX_SECONDARY: usize = 1;
    // Use fixed values to verify storage delta updates.
    const INITIAL_SLOT_VALUES: [u64; 4] = [100, 200, 300, 400];
    const UPDATED_SLOT_VALUES: [u64; 4] = [111, 222, 333, 444];
    // Use fixed delta values to validate nonce and vault changes.
    const NONCE_DELTA: u64 = 5;
    const VAULT_AMOUNT: u64 = 500;

    let mut conn = setup_test_db();

    // Create an account with value slots only (no map slots to avoid SmtForest complexity)
    let slot_value_initial = Word::from([
        Felt::new(INITIAL_SLOT_VALUES[0]),
        Felt::new(INITIAL_SLOT_VALUES[1]),
        Felt::new(INITIAL_SLOT_VALUES[2]),
        Felt::new(INITIAL_SLOT_VALUES[3]),
    ]);

    let component_storage = vec![
        StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX_PRIMARY), slot_value_initial),
        StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX_SECONDARY), EMPTY_WORD),
    ];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "pub proc foo push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test")
            .with_supported_type(AccountType::RegularAccountImmutableCode),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let block_1 = BlockNumber::from(BLOCK_NUM_1);
    let block_2 = BlockNumber::from(BLOCK_NUM_2);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    // Insert the initial account at block 1 (full state) - no vault assets
    let delta_initial = AccountDelta::try_from(account.clone()).unwrap();
    let account_update_initial = BlockAccountUpdate::new(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Delta(delta_initial),
    );
    upsert_accounts(&mut conn, &[account_update_initial], block_1).expect("Initial upsert failed");

    // Verify initial state
    let full_account_before =
        select_full_account(&mut conn, account.id()).expect("Failed to load full account");
    assert_eq!(full_account_before.nonce(), account.nonce());
    assert!(
        full_account_before.vault().assets().next().is_none(),
        "Vault should be empty initially"
    );

    // Create a partial delta to apply:
    // - Increment nonce by 5
    // - Update the first value slot
    // - Add 500 tokens to the vault (starting from empty)

    let new_slot_value = Word::from([
        Felt::new(UPDATED_SLOT_VALUES[0]),
        Felt::new(UPDATED_SLOT_VALUES[1]),
        Felt::new(UPDATED_SLOT_VALUES[2]),
        Felt::new(UPDATED_SLOT_VALUES[3]),
    ]);
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    // Find the slot name from the account's storage
    let value_slot_name =
        full_account_before.storage().slots().iter().next().unwrap().name().clone();

    // Build the storage delta (value slot update only)
    let storage_delta = {
        let deltas = BTreeMap::from_iter([(
            value_slot_name.clone(),
            StorageSlotDelta::Value(new_slot_value),
        )]);
        AccountStorageDelta::from_raw(deltas)
    };

    // Build the vault delta (add 500 tokens to empty vault)
    let vault_delta = {
        let mut delta = AccountVaultDelta::default();
        let asset = Asset::Fungible(FungibleAsset::new(faucet_id, VAULT_AMOUNT).unwrap());
        delta.add_asset(asset).unwrap();
        delta
    };

    // Create a partial delta
    let nonce_delta = Felt::new(NONCE_DELTA);
    let partial_delta = AccountDelta::new(
        full_account_before.id(),
        storage_delta.clone(),
        vault_delta.clone(),
        nonce_delta,
    )
    .unwrap();
    assert!(!partial_delta.is_full_state(), "Delta should be partial, not full state");

    // Construct the expected final account by applying the delta
    let expected_nonce = Felt::new(full_account_before.nonce().as_int() + nonce_delta.as_int());
    let expected_code_commitment = full_account_before.code().commitment();

    let mut expected_account = full_account_before.clone();
    expected_account.apply_delta(&partial_delta).unwrap();
    let final_account_for_commitment = expected_account;

    let final_commitment = final_account_for_commitment.to_commitment();
    let expected_storage_commitment = final_account_for_commitment.storage().to_commitment();
    let expected_vault_root = final_account_for_commitment.vault().root();

    // ----- Apply the partial delta via upsert_accounts (optimized path) -----
    let account_update = BlockAccountUpdate::new(
        account.id(),
        final_commitment,
        AccountUpdateDetails::Delta(partial_delta),
    );
    upsert_accounts(&mut conn, &[account_update], block_2).expect("Partial delta upsert failed");

    // ----- VERIFY: Query the DB and check that optimized path produced correct results -----

    let (header_after, storage_header_after) =
        select_account_header_with_storage_header_at_block(&mut conn, account.id(), block_2)
            .expect("Query should succeed")
            .expect("Account should exist");

    // Verify nonce
    assert_eq!(
        header_after.nonce(),
        expected_nonce,
        "Nonce mismatch: optimized={:?}, expected={:?}",
        header_after.nonce(),
        expected_nonce
    );

    // Verify code commitment (should be unchanged)
    assert_eq!(
        header_after.code_commitment(),
        expected_code_commitment,
        "Code commitment mismatch"
    );

    // Verify storage header commitment
    assert_eq!(
        storage_header_after.to_commitment(),
        expected_storage_commitment,
        "Storage header commitment mismatch"
    );

    // Verify vault assets
    let vault_assets_after = select_account_vault_at_block(&mut conn, account.id(), block_2)
        .expect("Query vault should succeed");

    assert_eq!(vault_assets_after.len(), 1, "Should have 1 vault asset");
    assert_matches!(&vault_assets_after[0], Asset::Fungible(f) => {
        assert_eq!(f.faucet_id(), faucet_id, "Faucet ID should match");
        assert_eq!(f.amount(), VAULT_AMOUNT, "Amount should be 500");
    });

    // Verify the account commitment matches
    assert_eq!(
        header_after.to_commitment(),
        final_commitment,
        "Account commitment should match the expected final state"
    );

    // Also verify we can load the full account and it has correct state
    let full_account_after = select_full_account(&mut conn, account.id())
        .expect("Failed to load full account after update");

    assert_eq!(full_account_after.nonce(), expected_nonce, "Full account nonce mismatch");
    assert_eq!(
        full_account_after.storage().to_commitment(),
        expected_storage_commitment,
        "Full account storage commitment mismatch"
    );
    assert_eq!(
        full_account_after.vault().root(),
        expected_vault_root,
        "Full account vault root mismatch"
    );
}

#[test]
fn optimized_delta_updates_non_empty_vault() {
    const ACCOUNT_SEED: [u8; 32] = [40u8; 32];
    const BLOCK_NUM_1: u32 = 1;
    const BLOCK_NUM_2: u32 = 2;
    const NONCE_DELTA: u64 = 1;
    const INITIAL_AMOUNT: u64 = 700;
    const ADDED_AMOUNT: u64 = 250;
    const SLOT_INDEX: usize = 0;

    let mut conn = setup_test_db();

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let faucet_id_1 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
    let initial_asset = Asset::Fungible(FungibleAsset::new(faucet_id, INITIAL_AMOUNT).unwrap());

    let component_storage =
        vec![StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX), EMPTY_WORD)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "pub proc vault push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test")
            .with_supported_type(AccountType::RegularAccountImmutableCode),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .with_assets([initial_asset])
        .build_existing()
        .unwrap();

    let block_1 = BlockNumber::from(BLOCK_NUM_1);
    let block_2 = BlockNumber::from(BLOCK_NUM_2);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    let delta_initial = AccountDelta::try_from(account.clone()).unwrap();
    let account_update_initial = BlockAccountUpdate::new(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Delta(delta_initial),
    );
    upsert_accounts(&mut conn, &[account_update_initial], block_1).expect("Initial upsert failed");

    let full_account_before =
        select_full_account(&mut conn, account.id()).expect("Failed to load full account");

    let mut vault_delta = AccountVaultDelta::default();
    vault_delta
        .add_asset(Asset::Fungible(FungibleAsset::new(faucet_id_1, ADDED_AMOUNT).unwrap()))
        .unwrap();
    vault_delta
        .remove_asset(Asset::Fungible(FungibleAsset::new(faucet_id, INITIAL_AMOUNT).unwrap()))
        .unwrap();

    let partial_delta = AccountDelta::new(
        account.id(),
        AccountStorageDelta::new(),
        vault_delta,
        Felt::new(NONCE_DELTA),
    )
    .unwrap();

    let mut expected_account = full_account_before.clone();
    expected_account.apply_delta(&partial_delta).unwrap();
    let expected_commitment = expected_account.to_commitment();
    let expected_vault_root = expected_account.vault().root();

    let account_update = BlockAccountUpdate::new(
        account.id(),
        expected_commitment,
        AccountUpdateDetails::Delta(partial_delta),
    );
    upsert_accounts(&mut conn, &[account_update], block_2).expect("Partial delta upsert failed");

    let vault_assets_after = select_account_vault_at_block(&mut conn, account.id(), block_2)
        .expect("Query vault should succeed");

    assert_eq!(vault_assets_after.len(), 1, "Should have 1 vault asset");
    assert_matches!(&vault_assets_after[0], Asset::Fungible(f) => {
        assert_eq!(f.faucet_id(), faucet_id_1, "Faucet ID should match");
        assert_eq!(f.amount(), ADDED_AMOUNT, "Amount should match");
    });

    let full_account_after = select_full_account(&mut conn, account.id())
        .expect("Failed to load full account after update");

    assert_eq!(full_account_after.vault().root(), expected_vault_root);
    assert_eq!(full_account_after.to_commitment(), expected_commitment);
}

#[test]
fn optimized_delta_updates_storage_map_header() {
    // Use deterministic account seed to keep account IDs stable.
    const ACCOUNT_SEED: [u8; 32] = [30u8; 32];
    // Use fixed block numbers to ensure deterministic ordering.
    const BLOCK_NUM_1: u32 = 1;
    const BLOCK_NUM_2: u32 = 2;
    // Use explicit slot index to avoid magic numbers.
    const SLOT_INDEX_MAP: usize = 3;
    // Use fixed map values to validate root updates.
    const MAP_KEY_VALUES: [u64; 4] = [7, 0, 0, 0];
    const MAP_VALUE_INITIAL: [u64; 4] = [10, 20, 30, 40];
    const MAP_VALUE_UPDATED: [u64; 4] = [50, 60, 70, 80];
    // Use nonzero nonce delta (required when storage/vault changes).
    const NONCE_DELTA: u64 = 1;

    let mut conn = setup_test_db();

    let map_key = Word::from([
        Felt::new(MAP_KEY_VALUES[0]),
        Felt::new(MAP_KEY_VALUES[1]),
        Felt::new(MAP_KEY_VALUES[2]),
        Felt::new(MAP_KEY_VALUES[3]),
    ]);
    let map_value_initial = Word::from([
        Felt::new(MAP_VALUE_INITIAL[0]),
        Felt::new(MAP_VALUE_INITIAL[1]),
        Felt::new(MAP_VALUE_INITIAL[2]),
        Felt::new(MAP_VALUE_INITIAL[3]),
    ]);
    let map_value_updated = Word::from([
        Felt::new(MAP_VALUE_UPDATED[0]),
        Felt::new(MAP_VALUE_UPDATED[1]),
        Felt::new(MAP_VALUE_UPDATED[2]),
        Felt::new(MAP_VALUE_UPDATED[3]),
    ]);

    let storage_map = StorageMap::with_entries(vec![(map_key, map_value_initial)]).unwrap();
    let component_storage =
        vec![StorageSlot::with_map(StorageSlotName::mock(SLOT_INDEX_MAP), storage_map)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "pub proc map push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test")
            .with_supported_type(AccountType::RegularAccountImmutableCode),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let block_1 = BlockNumber::from(BLOCK_NUM_1);
    let block_2 = BlockNumber::from(BLOCK_NUM_2);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    let delta_initial = AccountDelta::try_from(account.clone()).unwrap();
    let account_update_initial = BlockAccountUpdate::new(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Delta(delta_initial),
    );
    upsert_accounts(&mut conn, &[account_update_initial], block_1).expect("Initial upsert failed");

    let full_account_before =
        select_full_account(&mut conn, account.id()).expect("Failed to load full account");

    let mut map_delta = StorageMapDelta::default();
    map_delta.insert(map_key, map_value_updated);
    let storage_delta = AccountStorageDelta::from_raw(BTreeMap::from_iter([(
        StorageSlotName::mock(SLOT_INDEX_MAP),
        StorageSlotDelta::Map(map_delta),
    )]));

    let partial_delta = AccountDelta::new(
        account.id(),
        storage_delta,
        AccountVaultDelta::default(),
        Felt::new(NONCE_DELTA),
    )
    .unwrap();

    let mut expected_account = full_account_before.clone();
    expected_account.apply_delta(&partial_delta).unwrap();
    let expected_commitment = expected_account.to_commitment();
    let expected_storage_commitment = expected_account.storage().to_commitment();

    let account_update = BlockAccountUpdate::new(
        account.id(),
        expected_commitment,
        AccountUpdateDetails::Delta(partial_delta),
    );
    upsert_accounts(&mut conn, &[account_update], block_2).expect("Partial delta upsert failed");

    let (header_after, storage_header_after) =
        select_account_header_with_storage_header_at_block(&mut conn, account.id(), block_2)
            .expect("Query should succeed")
            .expect("Account should exist");

    assert_eq!(
        storage_header_after.to_commitment(),
        expected_storage_commitment,
        "Storage commitment should match after map delta"
    );
    assert_eq!(
        header_after.to_commitment(),
        expected_commitment,
        "Account commitment should match after map delta"
    );
}

/// Tests that a private account update (no public state) is handled correctly.
///
/// Private accounts store only the account commitment, not the full state.
#[test]
fn upsert_private_account() {
    use miden_protocol::account::{AccountIdVersion, AccountStorageMode, AccountType};

    // Use deterministic account seed to keep account IDs stable.
    const ACCOUNT_ID_SEED: [u8; 15] = [20u8; 15];
    // Use fixed block number to keep test ordering deterministic.
    const BLOCK_NUM: u32 = 1;
    // Use fixed commitment values to validate storage behavior.
    const COMMITMENT_WORDS: [u64; 4] = [1, 2, 3, 4];

    let mut conn = setup_test_db();

    let block_num = BlockNumber::from(BLOCK_NUM);
    insert_block_header(&mut conn, block_num);

    // Create a private account ID
    let account_id = AccountId::dummy(
        ACCOUNT_ID_SEED,
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let account_commitment = Word::from([
        Felt::new(COMMITMENT_WORDS[0]),
        Felt::new(COMMITMENT_WORDS[1]),
        Felt::new(COMMITMENT_WORDS[2]),
        Felt::new(COMMITMENT_WORDS[3]),
    ]);

    // Insert as private account
    let account_update =
        BlockAccountUpdate::new(account_id, account_commitment, AccountUpdateDetails::Private);

    upsert_accounts(&mut conn, &[account_update], block_num)
        .expect("Private account upsert failed");

    // Verify the account exists and commitment matches

    let (stored_commitment, stored_nonce, stored_code): (Vec<u8>, Option<i64>, Option<Vec<u8>>) =
        accounts::table
            .filter(accounts::account_id.eq(account_id.to_bytes()))
            .filter(accounts::is_latest.eq(true))
            .select((accounts::account_commitment, accounts::nonce, accounts::code_commitment))
            .first(&mut conn)
            .expect("Account should exist in DB");

    assert_eq!(
        stored_commitment,
        account_commitment.to_bytes(),
        "Stored commitment should match"
    );

    // Private accounts have NULL for nonce, code_commitment, storage_header, vault_root
    assert!(stored_nonce.is_none(), "Private account should have NULL nonce");
    assert!(stored_code.is_none(), "Private account should have NULL code_commitment");
}

/// Tests that a full-state delta (new account creation) is handled correctly.
///
/// Full-state deltas contain the complete account state including code.
#[test]
fn upsert_full_state_delta() {
    // Use deterministic account seed to keep account IDs stable.
    const ACCOUNT_SEED: [u8; 32] = [20u8; 32];
    // Use fixed block number to keep test ordering deterministic.
    const BLOCK_NUM: u32 = 1;
    // Use fixed slot values to validate storage behavior.
    const SLOT_VALUES: [u64; 4] = [10, 20, 30, 40];
    // Use explicit slot index to avoid magic numbers.
    const SLOT_INDEX: usize = 0;

    let mut conn = setup_test_db();

    let block_num = BlockNumber::from(BLOCK_NUM);
    insert_block_header(&mut conn, block_num);

    // Create an account with storage
    let slot_value = Word::from([
        Felt::new(SLOT_VALUES[0]),
        Felt::new(SLOT_VALUES[1]),
        Felt::new(SLOT_VALUES[2]),
        Felt::new(SLOT_VALUES[3]),
    ]);
    let component_storage =
        vec![StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX), slot_value)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "pub proc bar push.2 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test")
            .with_supported_type(AccountType::RegularAccountImmutableCode),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    // Create a full-state delta from the account
    let delta = AccountDelta::try_from(account.clone()).unwrap();
    assert!(delta.is_full_state(), "Delta should be full state");

    let account_update = BlockAccountUpdate::new(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Delta(delta),
    );

    upsert_accounts(&mut conn, &[account_update], block_num)
        .expect("Full-state delta upsert failed");

    // Verify the account state was stored correctly
    let (header, storage_header) =
        select_account_header_with_storage_header_at_block(&mut conn, account.id(), block_num)
            .expect("Query should succeed")
            .expect("Account should exist");

    assert_eq!(header.nonce(), account.nonce(), "Nonce should match");
    assert_eq!(
        header.code_commitment(),
        account.code().commitment(),
        "Code commitment should match"
    );
    assert_eq!(
        storage_header.to_commitment(),
        account.storage().to_commitment(),
        "Storage commitment should match"
    );

    // Verify we can load the full account back
    let loaded_account =
        select_full_account(&mut conn, account.id()).expect("Should load full account");

    assert_eq!(loaded_account.nonce(), account.nonce());
    assert_eq!(loaded_account.code().commitment(), account.code().commitment());
    assert_eq!(loaded_account.storage().to_commitment(), account.storage().to_commitment());
}
