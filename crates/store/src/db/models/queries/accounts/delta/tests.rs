//!
//! Tests for delta update functionality.

use std::collections::BTreeMap;

use assert_matches::assert_matches;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountIdVersion,
    AccountPatch,
    AccountStoragePatch,
    AccountType,
    AccountUpdateDetails,
    AccountVaultPatch,
    AssetCallbackFlag,
    StorageMap,
    StorageMapKey,
    StorageMapPatch,
    StorageSlot,
    StorageSlotName,
    StorageSlotPatch,
    StorageValuePatch,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::{BlockAccountUpdate, BlockHeader, BlockNumber, ValidatorConfig};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{EMPTY_WORD, Felt, Word};
use miden_standards::account::auth::{Approver, AuthSingleSig};
use miden_standards::code_builder::CodeBuilder;

use crate::db::models::queries::accounts::{
    PrecomputedPublicAccountState,
    PrecomputedPublicAccountStates,
    VALID_FOREVER,
    select_account_header_with_storage_header_at_block,
    select_account_vault_at_block,
    select_full_account,
    upsert_accounts,
};
use crate::db::schema::accounts;
use crate::errors::DatabaseError;

fn block_account_update(
    account_id: AccountId,
    final_state_commitment: Word,
    details: AccountUpdateDetails,
) -> BlockAccountUpdate {
    BlockAccountUpdate::new(account_id, final_state_commitment, details)
        .expect("test account update should be valid")
}

fn setup_test_db() -> SqliteConnection {
    crate::db::migrations::test_connection()
}

fn insert_block_header(conn: &mut SqliteConnection, block_num: BlockNumber) {
    use crate::db::schema::block_headers;

    let secret_key = SigningKey::new();
    let block_header = BlockHeader::new(
        Word::default(),
        block_num,
        Word::default(),
        Word::default(),
        Word::default(),
        Word::default(),
        Word::default(),
        ValidatorConfig::new(vec![secret_key.public_key()], 1).unwrap(),
        test_fee_params(),
        test_protocol_config().to_commitment(),
        None,
        0,
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

fn precomputed_state_from_account(account: &Account) -> PrecomputedPublicAccountState {
    PrecomputedPublicAccountState {
        vault_root: account.vault().root(),
        storage_map_roots: account
            .storage()
            .slots()
            .iter()
            .filter_map(|slot| match slot.content() {
                miden_protocol::account::StorageSlotContent::Map(map) => {
                    Some((slot.name().clone(), map.root()))
                },
                miden_protocol::account::StorageSlotContent::Value(_) => None,
            })
            .collect(),
    }
}

fn precomputed_states_from_account(account: &Account) -> PrecomputedPublicAccountStates {
    [(account.id(), precomputed_state_from_account(account))]
        .into_iter()
        .collect::<PrecomputedPublicAccountStates>()
}

fn callback_enabled_faucet_id() -> AccountId {
    AccountId::dummy(
        [41u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Enabled,
    )
}

fn callback_delta_test_account(seed: [u8; 32], slot_index: usize) -> Account {
    let component_storage =
        vec![StorageSlot::with_value(StorageSlotName::mock(slot_index), EMPTY_WORD)];
    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc vault push.1 end")
        .unwrap();
    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    AccountBuilder::new(seed)
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap()
}

fn insert_public_account(conn: &mut SqliteConnection, block_num: BlockNumber, account: &Account) {
    let patch_initial = AccountPatch::try_from(account.clone()).unwrap();
    upsert_accounts(
        conn,
        &[block_account_update(
            account.id(),
            account.to_commitment(),
            AccountUpdateDetails::Public(patch_initial),
        )],
        block_num,
        &precomputed_states_from_account(account),
    )
    .expect("initial upsert failed");
}

fn apply_callback_delta(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    faucet_id: AccountId,
    block: BlockNumber,
    amount: u64,
    nonce_delta: u64,
) -> Account {
    let prev = select_full_account(conn, account_id).expect("load account");
    let callback_template = FungibleAsset::new(faucet_id, amount).unwrap();
    let prev_amount = prev
        .vault()
        .get(callback_template.id())
        .and_then(|asset| asset.as_fungible())
        .map_or(0, |asset| asset.amount().as_u64());

    let absolute_asset = Asset::from(FungibleAsset::new(faucet_id, prev_amount + amount).unwrap());
    let mut vault_patch = AccountVaultPatch::default();
    vault_patch.insert_asset(absolute_asset);
    let final_nonce = Felt::new_unchecked(prev.nonce().as_canonical_u64() + nonce_delta);
    let patch = AccountPatch::new(
        account_id,
        AccountStoragePatch::new(),
        vault_patch,
        None,
        Some(final_nonce),
    )
    .unwrap();

    let mut expected = prev.clone();
    expected.apply_patch(&patch).unwrap();
    let precomputed_public_states = precomputed_states_from_account(&expected);

    upsert_accounts(
        conn,
        &[block_account_update(
            account_id,
            expected.to_commitment(),
            AccountUpdateDetails::Public(patch),
        )],
        block,
        &precomputed_public_states,
    )
    .expect("partial delta upsert failed");

    let after = select_full_account(conn, account_id).expect("load account after");
    assert_eq!(after.vault().root(), expected.vault().root(), "vault root mismatch");
    assert_eq!(after.to_commitment(), expected.to_commitment(), "commitment mismatch");
    after
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
        Felt::new_unchecked(INITIAL_SLOT_VALUES[0]),
        Felt::new_unchecked(INITIAL_SLOT_VALUES[1]),
        Felt::new_unchecked(INITIAL_SLOT_VALUES[2]),
        Felt::new_unchecked(INITIAL_SLOT_VALUES[3]),
    ]);

    let component_storage = vec![
        StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX_PRIMARY), slot_value_initial),
        StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX_SECONDARY), EMPTY_WORD),
    ];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc foo push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let block_1 = BlockNumber::from(BLOCK_NUM_1);
    let block_2 = BlockNumber::from(BLOCK_NUM_2);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    // Insert the initial account at block 1 (full state) - no vault assets
    let patch_initial = AccountPatch::try_from(account.clone()).unwrap();
    let account_update_initial = block_account_update(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Public(patch_initial),
    );
    upsert_accounts(
        &mut conn,
        &[account_update_initial],
        block_1,
        &precomputed_states_from_account(&account),
    )
    .expect("Initial upsert failed");

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
        Felt::new_unchecked(UPDATED_SLOT_VALUES[0]),
        Felt::new_unchecked(UPDATED_SLOT_VALUES[1]),
        Felt::new_unchecked(UPDATED_SLOT_VALUES[2]),
        Felt::new_unchecked(UPDATED_SLOT_VALUES[3]),
    ]);
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    // Find the slot name from the account's storage
    let value_slot_name =
        full_account_before.storage().slots().iter().next().unwrap().name().clone();

    // Build the storage delta (value slot update only)
    let storage_patch = {
        let deltas = [(
            value_slot_name.clone(),
            StorageSlotPatch::Value(StorageValuePatch::Update { value: new_slot_value }),
        )]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
        AccountStoragePatch::from_raw(deltas).unwrap()
    };

    // Build the vault patch (the absolute end-state is 500 tokens, starting from an empty vault)
    let vault_patch = {
        let asset = Asset::from(FungibleAsset::new(faucet_id, VAULT_AMOUNT).unwrap());
        AccountVaultPatch::with_assets([asset])
    };

    // Create a partial patch
    let nonce_delta = Felt::new_unchecked(NONCE_DELTA);
    let expected_nonce = Felt::new_unchecked(
        full_account_before.nonce().as_canonical_u64() + nonce_delta.as_canonical_u64(),
    );
    let partial_patch = AccountPatch::new(
        full_account_before.id(),
        storage_patch,
        vault_patch,
        None,
        Some(expected_nonce),
    )
    .unwrap();
    assert!(!partial_patch.is_full_state(), "Patch should be partial, not full state");

    // Construct the expected final account by applying the patch
    let expected_code_commitment = full_account_before.code().commitment();

    let mut expected_account = full_account_before.clone();
    expected_account.apply_patch(&partial_patch).unwrap();
    let final_account_for_commitment = expected_account;

    let final_commitment = final_account_for_commitment.to_commitment();
    let expected_storage_commitment = final_account_for_commitment.storage().to_commitment();
    let expected_vault_root = final_account_for_commitment.vault().root();
    let precomputed_public_states = precomputed_states_from_account(&final_account_for_commitment);

    // ----- Apply the partial patch via upsert_accounts (optimized path) -----
    let account_update = block_account_update(
        account.id(),
        final_commitment,
        AccountUpdateDetails::Public(partial_patch),
    );
    upsert_accounts(&mut conn, &[account_update], block_2, &precomputed_public_states)
        .expect("Partial delta upsert failed");

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
    let fungible_asset = vault_assets_after[0].unwrap_fungible();
    assert_eq!(fungible_asset.faucet_id(), faucet_id, "Faucet ID should match");
    assert_eq!(fungible_asset.amount().as_u64(), VAULT_AMOUNT, "Amount should be 500");

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
#[expect(
    clippy::too_many_lines,
    reason = "test exercises vault deltas across multiple blocks"
)]
fn optimized_delta_updates_non_empty_vault() {
    const ACCOUNT_SEED: [u8; 32] = [40u8; 32];
    const BLOCK_NUM_1: u32 = 1;
    const BLOCK_NUM_2: u32 = 2;
    const BLOCK_NUM_3: u32 = 3;
    const NONCE_DELTA: u64 = 1;
    const INITIAL_AMOUNT: u64 = 700;
    const ADDED_AMOUNT_BLOCK_2: u64 = 250;
    const ADDED_AMOUNT_BLOCK_3: u64 = 150;
    const SLOT_INDEX: usize = 0;

    let mut conn = setup_test_db();

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let faucet_id_1 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
    let initial_asset = Asset::from(FungibleAsset::new(faucet_id, INITIAL_AMOUNT).unwrap());

    let component_storage =
        vec![StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX), EMPTY_WORD)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc vault push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .with_assets([initial_asset])
        .build_existing()
        .unwrap();

    let block_1 = BlockNumber::from(BLOCK_NUM_1);
    let block_2 = BlockNumber::from(BLOCK_NUM_2);
    let block_3 = BlockNumber::from(BLOCK_NUM_3);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);
    insert_block_header(&mut conn, block_3);

    // Block 1: insert full-state patch (initial account with 700 tokens of faucet_id)
    let patch_initial = AccountPatch::try_from(account.clone()).unwrap();
    let account_update_initial = block_account_update(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Public(patch_initial),
    );
    upsert_accounts(
        &mut conn,
        &[account_update_initial],
        block_1,
        &precomputed_states_from_account(&account),
    )
    .expect("Initial upsert failed");

    let full_account_before =
        select_full_account(&mut conn, account.id()).expect("Failed to load full account");

    // Block 2: partial patch — remove faucet_id (700), add faucet_id_1 (250)
    let removed_asset = Asset::from(FungibleAsset::new(faucet_id, INITIAL_AMOUNT).unwrap());
    let added_asset = Asset::from(FungibleAsset::new(faucet_id_1, ADDED_AMOUNT_BLOCK_2).unwrap());
    let mut vault_patch = AccountVaultPatch::default();
    vault_patch.insert_asset(added_asset);
    vault_patch.remove_asset(removed_asset.id());

    let final_nonce =
        Felt::new_unchecked(full_account_before.nonce().as_canonical_u64() + NONCE_DELTA);
    let partial_patch = AccountPatch::new(
        account.id(),
        AccountStoragePatch::new(),
        vault_patch,
        None,
        Some(final_nonce),
    )
    .unwrap();

    let mut expected_account = full_account_before.clone();
    expected_account.apply_patch(&partial_patch).unwrap();
    let expected_commitment = expected_account.to_commitment();
    let expected_vault_root = expected_account.vault().root();
    let precomputed_public_states = precomputed_states_from_account(&expected_account);

    let account_update = block_account_update(
        account.id(),
        expected_commitment,
        AccountUpdateDetails::Public(partial_patch),
    );
    upsert_accounts(&mut conn, &[account_update], block_2, &precomputed_public_states)
        .expect("Partial delta upsert failed");

    let vault_assets_after = select_account_vault_at_block(&mut conn, account.id(), block_2)
        .expect("Query vault should succeed");

    assert_eq!(vault_assets_after.len(), 1, "Should have 1 vault asset");
    let fungible_asset = vault_assets_after[0].unwrap_fungible();
    assert_eq!(fungible_asset.faucet_id(), faucet_id_1, "Faucet ID should match");
    assert_eq!(fungible_asset.amount().as_u64(), ADDED_AMOUNT_BLOCK_2, "Amount should match");

    let full_account_after = select_full_account(&mut conn, account.id())
        .expect("Failed to load full account after update");

    assert_eq!(full_account_after.vault().root(), expected_vault_root);
    assert_eq!(full_account_after.to_commitment(), expected_commitment);

    // Block 3: partial patch — add more of faucet_id_1 (150 more, total = 400)
    let mut vault_patch_3 = AccountVaultPatch::default();
    vault_patch_3.insert_asset(Asset::from(
        FungibleAsset::new(faucet_id_1, ADDED_AMOUNT_BLOCK_2 + ADDED_AMOUNT_BLOCK_3).unwrap(),
    ));

    let final_nonce_3 =
        Felt::new_unchecked(full_account_after.nonce().as_canonical_u64() + NONCE_DELTA);
    let partial_patch_3 = AccountPatch::new(
        account.id(),
        AccountStoragePatch::new(),
        vault_patch_3,
        None,
        Some(final_nonce_3),
    )
    .unwrap();

    let mut expected_after_3 = full_account_after.clone();
    expected_after_3.apply_patch(&partial_patch_3).unwrap();
    let commitment_3 = expected_after_3.to_commitment();
    let expected_vault_root_3 = expected_after_3.vault().root();
    let precomputed_public_states_3 = precomputed_states_from_account(&expected_after_3);

    let account_update_3 = block_account_update(
        account.id(),
        commitment_3,
        AccountUpdateDetails::Public(partial_patch_3),
    );
    upsert_accounts(&mut conn, &[account_update_3], block_3, &precomputed_public_states_3)
        .expect("Block 3 upsert failed");

    let full_account_final =
        select_full_account(&mut conn, account.id()).expect("Failed to load after block 3");

    let final_assets: Vec<Asset> = full_account_final.vault().assets().collect();
    assert_eq!(final_assets.len(), 1, "Should have exactly 1 vault asset");
    let fungible_asset = final_assets[0].unwrap_fungible();
    assert_eq!(fungible_asset.faucet_id(), faucet_id_1);
    assert_eq!(
        fungible_asset.amount().as_u64(),
        ADDED_AMOUNT_BLOCK_2 + ADDED_AMOUNT_BLOCK_3,
        "Expected total of 400"
    );

    assert_eq!(full_account_final.vault().root(), expected_vault_root_3);
    assert_eq!(full_account_final.to_commitment(), commitment_3);
}

/// The partial delta path must preserve a fungible asset's callback flag (part of its vault key)
/// across blocks, so the recomputed vault root and account commitment match the kernel's. Applies a
/// callback-enabled asset over two partial-delta blocks and checks the second one still matches.
#[test]
fn optimized_delta_updates_preserve_callback_flag() {
    const ACCOUNT_SEED: [u8; 32] = [41u8; 32];
    const NONCE_DELTA: u64 = 1;
    const ADDED_AMOUNT_BLOCK_2: u64 = 250;
    const ADDED_AMOUNT_BLOCK_3: u64 = 150;
    const SLOT_INDEX: usize = 0;

    let mut conn = setup_test_db();

    let block_1 = BlockNumber::from(1u32);
    let block_2 = BlockNumber::from(2u32);
    let block_3 = BlockNumber::from(3u32);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);
    insert_block_header(&mut conn, block_3);

    let faucet_id = callback_enabled_faucet_id();
    let account = callback_delta_test_account(ACCOUNT_SEED, SLOT_INDEX);
    insert_public_account(&mut conn, block_1, &account);

    apply_callback_delta(
        &mut conn,
        account.id(),
        faucet_id,
        block_2,
        ADDED_AMOUNT_BLOCK_2,
        NONCE_DELTA,
    );
    let final_account = apply_callback_delta(
        &mut conn,
        account.id(),
        faucet_id,
        block_3,
        ADDED_AMOUNT_BLOCK_3,
        NONCE_DELTA,
    );

    let final_assets: Vec<Asset> = final_account.vault().assets().collect();
    assert_eq!(final_assets.len(), 1, "Should have exactly 1 vault asset");
    let fungible_asset = final_assets[0].unwrap_fungible();
    assert_eq!(fungible_asset.faucet_id(), faucet_id);
    assert_eq!(
        fungible_asset.callbacks(),
        AssetCallbackFlag::Enabled,
        "callback flag must be preserved through delta application"
    );
    assert_eq!(fungible_asset.amount().as_u64(), ADDED_AMOUNT_BLOCK_2 + ADDED_AMOUNT_BLOCK_3);
}

#[test]
#[expect(clippy::too_many_lines)]
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

    let map_key = StorageMapKey::new(Word::from([
        Felt::new_unchecked(MAP_KEY_VALUES[0]),
        Felt::new_unchecked(MAP_KEY_VALUES[1]),
        Felt::new_unchecked(MAP_KEY_VALUES[2]),
        Felt::new_unchecked(MAP_KEY_VALUES[3]),
    ]));
    let map_value_initial = Word::from([
        Felt::new_unchecked(MAP_VALUE_INITIAL[0]),
        Felt::new_unchecked(MAP_VALUE_INITIAL[1]),
        Felt::new_unchecked(MAP_VALUE_INITIAL[2]),
        Felt::new_unchecked(MAP_VALUE_INITIAL[3]),
    ]);
    let map_value_updated = Word::from([
        Felt::new_unchecked(MAP_VALUE_UPDATED[0]),
        Felt::new_unchecked(MAP_VALUE_UPDATED[1]),
        Felt::new_unchecked(MAP_VALUE_UPDATED[2]),
        Felt::new_unchecked(MAP_VALUE_UPDATED[3]),
    ]);

    let storage_map = StorageMap::with_entries(vec![(map_key, map_value_initial)]).unwrap();
    let component_storage =
        vec![StorageSlot::with_map(StorageSlotName::mock(SLOT_INDEX_MAP), storage_map)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc map push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let block_1 = BlockNumber::from(BLOCK_NUM_1);
    let block_2 = BlockNumber::from(BLOCK_NUM_2);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    let patch_initial = AccountPatch::try_from(account.clone()).unwrap();
    let account_update_initial = block_account_update(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Public(patch_initial),
    );
    upsert_accounts(
        &mut conn,
        &[account_update_initial],
        block_1,
        &precomputed_states_from_account(&account),
    )
    .expect("Initial upsert failed");

    let full_account_before =
        select_full_account(&mut conn, account.id()).expect("Failed to load full account");

    let map_patch = StorageMapPatch::from_iters([], [(map_key, map_value_updated)]);
    let storage_patch = AccountStoragePatch::from_raw(
        [(StorageSlotName::mock(SLOT_INDEX_MAP), StorageSlotPatch::Map(map_patch))]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap();

    let final_nonce =
        Felt::new_unchecked(full_account_before.nonce().as_canonical_u64() + NONCE_DELTA);
    let partial_patch = AccountPatch::new(
        account.id(),
        storage_patch,
        AccountVaultPatch::default(),
        None,
        Some(final_nonce),
    )
    .unwrap();

    let mut expected_account = full_account_before.clone();
    expected_account.apply_patch(&partial_patch).unwrap();
    let expected_commitment = expected_account.to_commitment();
    let expected_storage_commitment = expected_account.storage().to_commitment();
    let precomputed_public_states = precomputed_states_from_account(&expected_account);

    let account_update = block_account_update(
        account.id(),
        expected_commitment,
        AccountUpdateDetails::Public(partial_patch),
    );
    upsert_accounts(&mut conn, &[account_update], block_2, &precomputed_public_states)
        .expect("Partial delta upsert failed");

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

#[test]
fn apply_storage_patch_with_roots_uses_precomputed_map_root() {
    use miden_protocol::account::{AccountStorageHeader, StorageSlotHeader, StorageSlotType};

    use super::apply_storage_patch_with_roots;

    let slot_name = StorageSlotName::mock(70);
    let key = StorageMapKey::new(Word::from([Felt::new_unchecked(71); 4]));
    let old_value = Word::from([Felt::new_unchecked(72); 4]);
    let new_value = Word::from([Felt::new_unchecked(73); 4]);
    let old_root = StorageMap::with_entries([(key, old_value)]).unwrap().root();
    let new_root = StorageMap::with_entries([(key, new_value)]).unwrap().root();
    let header = AccountStorageHeader::new(vec![StorageSlotHeader::new(
        slot_name.clone(),
        StorageSlotType::Map,
        old_root,
    )])
    .unwrap();
    let patch = AccountStoragePatch::from_raw(
        [(
            slot_name.clone(),
            StorageSlotPatch::Map(StorageMapPatch::from_iters([], [(key, new_value)])),
        )]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    )
    .unwrap();
    let precomputed_roots = [(slot_name.clone(), new_root)].into_iter().collect::<BTreeMap<_, _>>();

    let new_header = apply_storage_patch_with_roots(&header, &patch, &precomputed_roots).unwrap();

    let updated_slot = new_header.find_slot_header_by_name(&slot_name).unwrap();
    assert_eq!(updated_slot.value(), new_root);
    assert_eq!(updated_slot.slot_type(), StorageSlotType::Map);
}

#[test]
fn partial_public_upsert_requires_precomputed_state() {
    const ACCOUNT_SEED: [u8; 32] = [80u8; 32];
    const SLOT_INDEX: usize = 0;

    let mut conn = setup_test_db();
    let block_1 = BlockNumber::from(1u32);
    let block_2 = BlockNumber::from(2u32);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    let component_storage =
        vec![StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX), EMPTY_WORD)];
    let account_component_code = CodeBuilder::default()
        .compile_component_code(
            "test::interface",
            "@account_procedure pub proc required push.1 end",
        )
        .unwrap();
    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();
    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let patch_initial = AccountPatch::try_from(account.clone()).unwrap();
    upsert_accounts(
        &mut conn,
        &[block_account_update(
            account.id(),
            account.to_commitment(),
            AccountUpdateDetails::Public(patch_initial),
        )],
        block_1,
        &precomputed_states_from_account(&account),
    )
    .expect("initial full-state upsert failed");

    let mut current_account = select_full_account(&mut conn, account.id()).unwrap();
    let patch = AccountPatch::new(
        account.id(),
        AccountStoragePatch::new(),
        AccountVaultPatch::default(),
        None,
        Some(Felt::new_unchecked(current_account.nonce().as_canonical_u64() + 1)),
    )
    .unwrap();
    current_account.apply_patch(&patch).unwrap();

    let err = upsert_accounts(
        &mut conn,
        &[block_account_update(
            account.id(),
            current_account.to_commitment(),
            AccountUpdateDetails::Public(patch),
        )],
        block_2,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect_err("partial public upsert should require precomputed roots");

    assert_matches!(err, DatabaseError::DataCorrupted(message) if message.contains("missing precomputed public account state"));
}

#[test]
fn partial_public_upsert_rejects_bad_precomputed_root() {
    const ACCOUNT_SEED: [u8; 32] = [81u8; 32];
    const SLOT_INDEX: usize = 0;

    let mut conn = setup_test_db();
    let block_1 = BlockNumber::from(1u32);
    let block_2 = BlockNumber::from(2u32);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    let component_storage =
        vec![StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX), EMPTY_WORD)];
    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc badroot push.1 end")
        .unwrap();
    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();
    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let patch_initial = AccountPatch::try_from(account.clone()).unwrap();
    upsert_accounts(
        &mut conn,
        &[block_account_update(
            account.id(),
            account.to_commitment(),
            AccountUpdateDetails::Public(patch_initial),
        )],
        block_1,
        &precomputed_states_from_account(&account),
    )
    .expect("initial full-state upsert failed");

    let mut expected_account = select_full_account(&mut conn, account.id()).unwrap();
    let patch = AccountPatch::new(
        account.id(),
        AccountStoragePatch::new(),
        AccountVaultPatch::default(),
        None,
        Some(Felt::new_unchecked(expected_account.nonce().as_canonical_u64() + 1)),
    )
    .unwrap();
    expected_account.apply_patch(&patch).unwrap();

    let mut precomputed = precomputed_states_from_account(&expected_account);
    precomputed.get_mut(&account.id()).unwrap().vault_root =
        Word::from([Felt::new_unchecked(999); 4]);

    let err = upsert_accounts(
        &mut conn,
        &[block_account_update(
            account.id(),
            expected_account.to_commitment(),
            AccountUpdateDetails::Public(patch),
        )],
        block_2,
        &precomputed,
    )
    .expect_err("bad precomputed roots should be validated against the final commitment");

    assert_matches!(err, DatabaseError::AccountCommitmentsMismatch { .. });
}

/// Tests that a private account update (no public state) is handled correctly.
///
/// Private accounts store only the account commitment, not the full state.
#[test]
fn upsert_private_account() {
    use miden_protocol::account::{AccountIdVersion, AccountType};

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
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );

    let account_commitment = Word::from([
        Felt::new_unchecked(COMMITMENT_WORDS[0]),
        Felt::new_unchecked(COMMITMENT_WORDS[1]),
        Felt::new_unchecked(COMMITMENT_WORDS[2]),
        Felt::new_unchecked(COMMITMENT_WORDS[3]),
    ]);

    // Insert as private account
    let account_update =
        block_account_update(account_id, account_commitment, AccountUpdateDetails::Private);

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("Private account upsert failed");

    // Verify the account exists and commitment matches

    let (stored_commitment, stored_nonce, stored_code): (Vec<u8>, Option<i64>, Option<Vec<u8>>) =
        accounts::table
            .filter(accounts::account_id.eq(account_id.to_bytes()))
            .filter(accounts::valid_until.eq(VALID_FOREVER))
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
        Felt::new_unchecked(SLOT_VALUES[0]),
        Felt::new_unchecked(SLOT_VALUES[1]),
        Felt::new_unchecked(SLOT_VALUES[2]),
        Felt::new_unchecked(SLOT_VALUES[3]),
    ]);
    let component_storage =
        vec![StorageSlot::with_value(StorageSlotName::mock(SLOT_INDEX), slot_value)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc bar push.2 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new(ACCOUNT_SEED)
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    // Create a full-state patch from the account
    let patch = AccountPatch::try_from(account.clone()).unwrap();
    assert!(patch.is_full_state(), "Patch should be full state");

    let account_update = block_account_update(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    );

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &precomputed_states_from_account(&account),
    )
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

/// Tests that `apply_storage_patch` mirrors the protocol's patch semantics for slot creation,
/// update, and removal, for both value and map slots.
#[test]
fn apply_storage_patch_handles_create_update_and_remove() {
    use std::collections::HashMap;

    use miden_protocol::account::{
        AccountStorageHeader,
        StorageMapPatchEntries,
        StorageSlotHeader,
        StorageSlotType,
    };

    use super::apply_storage_patch;

    let removed_value_name = StorageSlotName::mock(10);
    let removed_map_name = StorageSlotName::mock(11);
    let updated_value_name = StorageSlotName::mock(12);
    let created_value_name = StorageSlotName::mock(13);
    let created_map_name = StorageSlotName::mock(14);

    let old_value = Word::from([Felt::new_unchecked(1); 4]);
    let updated_value = Word::from([Felt::new_unchecked(2); 4]);
    let created_value = Word::from([Felt::new_unchecked(3); 4]);
    let old_map_root = StorageMap::with_entries(std::iter::empty()).unwrap().root();

    let mut slots = vec![
        StorageSlotHeader::new(removed_value_name.clone(), StorageSlotType::Value, old_value),
        StorageSlotHeader::new(removed_map_name.clone(), StorageSlotType::Map, old_map_root),
        StorageSlotHeader::new(updated_value_name.clone(), StorageSlotType::Value, old_value),
    ];
    slots.sort_by_key(StorageSlotHeader::id);
    let header = AccountStorageHeader::new(slots).unwrap();

    let patch = AccountStoragePatch::from_raw(
        [
            (removed_value_name.clone(), StorageSlotPatch::Value(StorageValuePatch::Remove)),
            (removed_map_name.clone(), StorageSlotPatch::Map(StorageMapPatch::Remove)),
            (
                updated_value_name.clone(),
                StorageSlotPatch::Value(StorageValuePatch::Update { value: updated_value }),
            ),
            (
                created_value_name.clone(),
                StorageSlotPatch::Value(StorageValuePatch::Create { value: created_value }),
            ),
            (
                created_map_name.clone(),
                StorageSlotPatch::Map(StorageMapPatch::Create {
                    entries: StorageMapPatchEntries::new(),
                }),
            ),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    )
    .unwrap();

    let new_header =
        apply_storage_patch(&header, &patch, &HashMap::new()).expect("patch should apply");

    assert_eq!(new_header.num_slots(), 3, "two slots removed, two created");
    assert!(
        new_header.find_slot_header_by_name(&removed_value_name).is_none(),
        "removed value slot should be dropped from the header"
    );
    assert!(
        new_header.find_slot_header_by_name(&removed_map_name).is_none(),
        "removed map slot should be dropped from the header"
    );

    let updated_slot = new_header.find_slot_header_by_name(&updated_value_name).unwrap();
    assert_eq!(updated_slot.value(), updated_value);
    assert_eq!(updated_slot.slot_type(), StorageSlotType::Value);

    let created_slot = new_header.find_slot_header_by_name(&created_value_name).unwrap();
    assert_eq!(created_slot.value(), created_value);
    assert_eq!(created_slot.slot_type(), StorageSlotType::Value);

    let created_map_slot = new_header.find_slot_header_by_name(&created_map_name).unwrap();
    assert_eq!(created_map_slot.value(), old_map_root, "empty map root expected");
    assert_eq!(created_map_slot.slot_type(), StorageSlotType::Map);
}
