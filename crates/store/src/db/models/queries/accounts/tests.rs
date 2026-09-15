//! Tests for the `accounts` module, specifically for account storage and historical queries.

use std::collections::BTreeMap;

use diesel::query_dsl::methods::SelectDsl;
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl};
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
    AccountStorage,
    AccountStorageHeader,
    AccountStoragePatch,
    AccountType,
    AccountUpdateDetails,
    AccountVaultPatch,
    AssetCallbackFlag,
    StorageMap,
    StorageMapKey,
    StorageMapPatch,
    StorageSlot,
    StorageSlotContent,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
};
use miden_protocol::asset::{NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::block::{BlockAccountUpdate, BlockHeader, BlockNumber, ValidatorConfig};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{EMPTY_WORD, Felt, Word};
use miden_standards::account::auth::{Approver, AuthSingleSig};
use miden_standards::code_builder::CodeBuilder;

use super::*;
use crate::db::models::conv::SqlTypeConvert;
use crate::db::schema;
use crate::errors::DatabaseError;

fn setup_test_db() -> SqliteConnection {
    crate::db::migrations::test_connection()
}

fn block_account_update(
    account_id: AccountId,
    final_state_commitment: Word,
    details: AccountUpdateDetails,
) -> BlockAccountUpdate {
    BlockAccountUpdate::new(account_id, final_state_commitment, details)
        .expect("test account update should be valid")
}

/// Test helper: reconstructs account storage at a given block from DB.
///
/// Reads `accounts.storage_header` and `account_storage_map_values` to reconstruct
/// the full `AccountStorage` at the specified block.
fn reconstruct_account_storage_at_block(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<AccountStorage, DatabaseError> {
    use schema::account_storage_map_values as t;

    let account_id_bytes = account_id.to_bytes();
    let block_num_sql = block_num.to_raw_sql();

    // Query storage header blob for this account at or before this block
    let storage_blob: Option<Vec<u8>> =
        SelectDsl::select(schema::accounts::table, schema::accounts::storage_header)
            .filter(schema::accounts::account_id.eq(&account_id_bytes))
            .filter(schema::accounts::block_num.le(block_num_sql))
            .order(schema::accounts::block_num.desc())
            .limit(1)
            .first(conn)
            .optional()?
            .flatten();

    let Some(blob) = storage_blob else {
        return Ok(AccountStorage::new(Vec::new())?);
    };

    let header = AccountStorageHeader::read_from_bytes(&blob)?;

    // Query all map values for this account up to and including this block.
    let map_values: Vec<(i64, String, Vec<u8>, Vec<u8>)> =
        SelectDsl::select(t::table, (t::block_num, t::slot_name, t::key, t::value))
            .filter(t::account_id.eq(&account_id_bytes).and(t::block_num.le(block_num_sql)))
            .order((t::slot_name.asc(), t::key.asc(), t::block_num.desc()))
            .load(conn)?;

    // For each (slot_name, key) pair, keep only the latest entry
    let mut latest_map_entries: BTreeMap<(StorageSlotName, StorageMapKey), Word> = BTreeMap::new();
    for (_, slot_name_str, key_bytes, value_bytes) in map_values {
        let slot_name: StorageSlotName = slot_name_str.parse().map_err(|_| {
            DatabaseError::DataCorrupted(format!("Invalid slot name: {slot_name_str}"))
        })?;
        let key = StorageMapKey::read_from_bytes(&key_bytes)?;
        let value = Word::read_from_bytes(&value_bytes)?;
        latest_map_entries.entry((slot_name, key)).or_insert(value);
    }

    // Group entries by slot name
    let mut map_entries_by_slot: BTreeMap<StorageSlotName, Vec<(StorageMapKey, Word)>> =
        BTreeMap::new();
    for ((slot_name, key), value) in latest_map_entries {
        map_entries_by_slot.entry(slot_name).or_default().push((key, value));
    }

    // Reconstruct StorageSlots from header slots + map entries
    let mut slots = Vec::new();
    for slot_header in header.slots() {
        let slot = match slot_header.slot_type() {
            StorageSlotType::Value => {
                StorageSlot::with_value(slot_header.name().clone(), slot_header.value())
            },
            StorageSlotType::Map => {
                let entries = map_entries_by_slot.remove(slot_header.name()).unwrap_or_default();
                let storage_map = StorageMap::with_entries(entries)?;
                StorageSlot::with_map(slot_header.name().clone(), storage_map)
            },
        };
        slots.push(slot);
    }

    Ok(AccountStorage::new(slots)?)
}

fn create_test_account_with_storage() -> (Account, AccountId) {
    // Create a simple public account with one value storage slot
    let account_id = AccountId::dummy(
        [1u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );

    let storage_value = Word::from([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let component_storage = vec![StorageSlot::with_value(StorageSlotName::mock(0), storage_value)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc foo push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    (account, account_id)
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
                StorageSlotContent::Map(map) => Some((slot.name().clone(), map.root())),
                StorageSlotContent::Value(_) => None,
            })
            .collect(),
    }
}

fn precomputed_states_from_account(account: &Account) -> PrecomputedPublicAccountStates {
    [(account.id(), precomputed_state_from_account(account))]
        .into_iter()
        .collect::<PrecomputedPublicAccountStates>()
}

fn create_account_with_map_storage(
    slot_name: StorageSlotName,
    entries: Vec<(StorageMapKey, Word)>,
) -> Account {
    let storage_map = StorageMap::with_entries(entries).unwrap();
    let component_storage = vec![StorageSlot::with_map(slot_name, storage_map)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc map push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    AccountBuilder::new([9u8; 32])
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap()
}

fn assert_storage_map_slot_entries(
    storage: &AccountStorage,
    slot_name: &StorageSlotName,
    expected: &BTreeMap<StorageMapKey, Word>,
) {
    let slot = storage
        .slots()
        .iter()
        .find(|slot| slot.name() == slot_name)
        .expect("expected storage slot");

    let StorageSlotContent::Map(storage_map) = slot.content() else {
        panic!("expected map slot");
    };

    let entries = storage_map
        .entries()
        .map(|(key, value)| (*key, *value))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(&entries, expected, "map entries mismatch");
}

// ACCOUNT HEADER AT BLOCK TESTS
// ================================================================================================

#[test]
fn select_account_header_at_block_returns_none_for_nonexistent() {
    let mut conn = setup_test_db();
    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    let account_id = AccountId::dummy(
        [99u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );

    // Query for a non-existent account
    let result =
        select_account_header_with_storage_header_at_block(&mut conn, account_id, block_num)
            .expect("Query should succeed");

    assert!(result.is_none(), "Should return None for non-existent account");
}

#[test]
fn select_account_header_at_block_returns_correct_header() {
    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    // Insert the account
    let patch = AccountPatch::try_from(account.clone()).unwrap();
    let account_update = block_account_update(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    );

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("upsert_accounts failed");

    // Query the account header
    let (header, _storage_header) =
        select_account_header_with_storage_header_at_block(&mut conn, account_id, block_num)
            .expect("Query should succeed")
            .expect("Header should exist");

    assert_eq!(header.id(), account_id, "Account ID should match");
    assert_eq!(header.nonce(), account.nonce(), "Nonce should match");
    assert_eq!(
        header.code_commitment(),
        account.code().commitment(),
        "Code commitment should match"
    );
}

#[test]
fn select_account_header_at_block_historical_query() {
    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    let block_num_1 = BlockNumber::from_epoch(0);
    let block_num_2 = BlockNumber::from_epoch(1);
    insert_block_header(&mut conn, block_num_1);
    insert_block_header(&mut conn, block_num_2);

    // Insert the account at block 1
    let nonce_1 = account.nonce();
    let patch_1 = AccountPatch::try_from(account.clone()).unwrap();
    let account_update_1 = block_account_update(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Public(patch_1),
    );

    upsert_accounts(
        &mut conn,
        &[account_update_1],
        block_num_1,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("First upsert failed");

    // Query at block 1 - should return the account
    let (header_1, _) =
        select_account_header_with_storage_header_at_block(&mut conn, account_id, block_num_1)
            .expect("Query should succeed")
            .expect("Header should exist at block 1");

    assert_eq!(header_1.nonce(), nonce_1, "Nonce at block 1 should match");

    // Query at block 2 - should return the same account (most recent before block 2)
    let (header_2, _) =
        select_account_header_with_storage_header_at_block(&mut conn, account_id, block_num_2)
            .expect("Query should succeed")
            .expect("Header should exist at block 2");

    assert_eq!(header_2.nonce(), nonce_1, "Nonce at block 2 should match block 1");
}

// ACCOUNT VAULT AT BLOCK TESTS
// ================================================================================================

#[test]
fn select_account_vault_at_block_empty() {
    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    // Insert account without vault assets
    let patch = AccountPatch::try_from(account.clone()).unwrap();
    let account_update = block_account_update(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    );

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("upsert_accounts failed");

    // Query vault - should return empty (the test account has no assets)
    let assets = select_account_vault_at_block(&mut conn, account_id, block_num)
        .expect("Query should succeed");

    assert!(assets.is_empty(), "Account should have no assets");
}

// ACCOUNT STORAGE AT BLOCK TESTS
// ================================================================================================

#[test]
fn upsert_accounts_inserts_storage_header() {
    let mut conn = setup_test_db();
    let (account, account_id) = create_test_account_with_storage();

    // Block 1
    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    let storage_commitment_original = account.storage().to_commitment();
    let storage_slots_len = account.storage().slots().len();
    let account_commitment = account.to_commitment();

    // Create full state patch from the account
    let patch = AccountPatch::try_from(account).unwrap();
    assert!(patch.is_full_state(), "Patch should be full state");

    let account_update =
        block_account_update(account_id, account_commitment, AccountUpdateDetails::Public(patch));

    // Upsert account
    let result = upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    );
    assert!(result.is_ok(), "upsert_accounts failed: {:?}", result.err());
    assert_eq!(result.unwrap(), 1, "Expected 1 account to be inserted");

    // Query storage header back
    let queried_storage = select_latest_account_storage(&mut conn, account_id)
        .expect("Failed to query storage header");

    // Verify storage commitment matches
    assert_eq!(
        queried_storage.to_commitment(),
        storage_commitment_original,
        "Storage commitment mismatch"
    );

    // Verify number of slots matches
    assert_eq!(queried_storage.slots().len(), storage_slots_len, "Storage slots count mismatch");

    // Verify exactly 1 latest account with storage exists
    let header_count: i64 = schema::accounts::table
        .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
        .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
        .filter(schema::accounts::storage_header.is_not_null())
        .count()
        .get_result(&mut conn)
        .expect("Failed to count accounts with storage");

    assert_eq!(header_count, 1, "Expected exactly 1 latest account with storage");
}

#[test]
fn upsert_accounts_closes_previous_validity_interval() {
    let mut conn = setup_test_db();
    let (account, account_id) = create_test_account_with_storage();

    // Block 1 and 2
    let block_num_1 = BlockNumber::from_epoch(0);
    let block_num_2 = BlockNumber::from_epoch(1);

    insert_block_header(&mut conn, block_num_1);
    insert_block_header(&mut conn, block_num_2);

    // Save storage commitment before moving account
    let storage_commitment_1 = account.storage().to_commitment();
    let account_commitment_1 = account.to_commitment();

    // First update with original account - full state patch
    let precomputed_1 = precomputed_states_from_account(&account);
    let patch_1 = AccountPatch::try_from(account).unwrap();

    let account_update_1 = block_account_update(
        account_id,
        account_commitment_1,
        AccountUpdateDetails::Public(patch_1),
    );

    upsert_accounts(&mut conn, &[account_update_1], block_num_1, &precomputed_1)
        .expect("First upsert failed");

    // Create modified account with different storage value
    let storage_value_modified = Word::from([
        Felt::new_unchecked(10),
        Felt::new_unchecked(20),
        Felt::new_unchecked(30),
        Felt::new_unchecked(40),
    ]);
    let component_storage_modified =
        vec![StorageSlot::with_value(StorageSlotName::mock(0), storage_value_modified)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc foo push.1 end")
        .unwrap();

    let component_2 = AccountComponent::new(
        account_component_code,
        component_storage_modified,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account_2 = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::Public)
        .with_component(component_2)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let storage_commitment_2 = account_2.storage().to_commitment();
    let account_commitment_2 = account_2.to_commitment();

    // Second update with modified account - full state patch
    let precomputed_2 = precomputed_states_from_account(&account_2);
    let patch_2 = AccountPatch::try_from(account_2).unwrap();

    let account_update_2 = block_account_update(
        account_id,
        account_commitment_2,
        AccountUpdateDetails::Public(patch_2),
    );

    upsert_accounts(&mut conn, &[account_update_2], block_num_2, &precomputed_2)
        .expect("Second upsert failed");

    // Verify 2 total account rows exist (both historical records)
    let total_accounts: i64 = schema::accounts::table
        .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
        .count()
        .get_result(&mut conn)
        .expect("Failed to count total accounts");

    assert_eq!(total_accounts, 2, "Expected 2 total account records");

    // Verify only 1 is open-ended (latest)
    let latest_accounts: i64 = schema::accounts::table
        .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
        .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
        .count()
        .get_result(&mut conn)
        .expect("Failed to count latest accounts");

    assert_eq!(latest_accounts, 1, "Expected exactly 1 latest account");

    // Verify latest storage matches second update
    let latest_storage = select_latest_account_storage(&mut conn, account_id)
        .expect("Failed to query latest storage");

    assert_eq!(
        latest_storage.to_commitment(),
        storage_commitment_2,
        "Latest storage should match second update"
    );

    // Verify historical query returns first update
    let storage_at_block_1 =
        reconstruct_account_storage_at_block(&mut conn, account_id, block_num_1)
            .expect("Failed to query storage at block 1");

    assert_eq!(
        storage_at_block_1.to_commitment(),
        storage_commitment_1,
        "Storage at block 1 should match first update"
    );
}

#[test]
fn upsert_accounts_with_multiple_storage_slots() {
    let mut conn = setup_test_db();

    // Create account with 3 storage slots
    let account_id = AccountId::dummy(
        [2u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );

    let slot_value_1 = Word::from([1, 2, 3, 4u32]);
    let slot_value_2 = Word::from([5, 6, 7, 8u32]);
    let slot_value_3 = Word::from([9, 10, 11, 12u32]);

    let component_storage = vec![
        StorageSlot::with_value(StorageSlotName::mock(0), slot_value_1),
        StorageSlot::with_value(StorageSlotName::mock(1), slot_value_2),
        StorageSlot::with_value(StorageSlotName::mock(2), slot_value_3),
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

    let account = AccountBuilder::new([2u8; 32])
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    let storage_commitment = account.storage().to_commitment();
    let account_commitment = account.to_commitment();
    let patch = AccountPatch::try_from(account).unwrap();

    let account_update =
        block_account_update(account_id, account_commitment, AccountUpdateDetails::Public(patch));

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("Upsert with multiple storage slots failed");

    // Query back and verify
    let queried_storage =
        select_latest_account_storage(&mut conn, account_id).expect("Failed to query storage");

    assert_eq!(
        queried_storage.to_commitment(),
        storage_commitment,
        "Storage commitment mismatch"
    );

    // Note: AuthSingleSig adds 2 storage slots (pub key + scheme id), so 3 component slots + 2 auth
    // = 5 total
    assert_eq!(
        queried_storage.slots().len(),
        5,
        "Expected 5 storage slots (3 component + 2 auth)"
    );

    // The storage commitment matching proves that all values are correctly preserved. We don't
    // check individual slot values by index since slot ordering may vary.
}

#[test]
fn upsert_accounts_with_empty_storage() {
    let mut conn = setup_test_db();

    // Create account with no component storage slots (only auth slot)
    let account_id = AccountId::dummy(
        [3u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc foo push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        vec![],
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new([3u8; 32])
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    let storage_commitment = account.storage().to_commitment();
    let account_commitment = account.to_commitment();
    let patch = AccountPatch::try_from(account).unwrap();

    let account_update =
        block_account_update(account_id, account_commitment, AccountUpdateDetails::Public(patch));

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("Upsert with empty storage failed");

    // Query back and verify
    let queried_storage =
        select_latest_account_storage(&mut conn, account_id).expect("Failed to query storage");

    assert_eq!(
        queried_storage.to_commitment(),
        storage_commitment,
        "Storage commitment mismatch for empty storage"
    );

    // Note: AuthSingleSig adds 2 storage slots (pub key + scheme id)
    assert_eq!(queried_storage.slots().len(), 2, "Expected 2 storage slots (auth component)");

    // Verify the storage header blob exists in database
    let storage_header_exists: Option<bool> = SelectDsl::select(
        schema::accounts::table
            .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
            .filter(schema::accounts::valid_until.eq(VALID_FOREVER)),
        schema::accounts::storage_header.is_not_null(),
    )
    .first(&mut conn)
    .optional()
    .expect("Failed to check storage header existence");

    assert_eq!(
        storage_header_exists,
        Some(true),
        "Storage header blob should exist even for empty storage"
    );
}

// STORAGE MAP LATEST ACCOUNT QUERY TESTS
// ================================================================================================

#[test]
fn select_latest_account_storage_ordering_semantics() {
    let mut conn = setup_test_db();
    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    let slot_name = StorageSlotName::mock(0);
    let key_1 = StorageMapKey::from_index(1);
    let key_2 = StorageMapKey::from_index(2);
    let key_3 = StorageMapKey::from_index(3);

    let value_1 = Word::from([Felt::new_unchecked(10), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let value_2 = Word::from([Felt::new_unchecked(20), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let value_3 = Word::from([Felt::new_unchecked(30), Felt::ZERO, Felt::ZERO, Felt::ZERO]);

    let mut entries = vec![(key_2, value_2), (key_1, value_1), (key_3, value_3)];
    entries.reverse();

    let account = create_account_with_map_storage(slot_name.clone(), entries.clone());
    let account_id = account.id();
    let account_commitment = account.to_commitment();

    let mut reversed_entries = entries.clone();
    reversed_entries.reverse();
    let reordered_account = create_account_with_map_storage(slot_name.clone(), reversed_entries);
    assert_eq!(
        account.storage().to_commitment(),
        reordered_account.storage().to_commitment(),
        "storage commitments should be order-independent"
    );

    let patch = AccountPatch::try_from(account).unwrap();
    let account_update =
        block_account_update(account_id, account_commitment, AccountUpdateDetails::Public(patch));

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("upsert_accounts failed");

    let storage =
        select_latest_account_storage(&mut conn, account_id).expect("Failed to query storage");

    let expected = entries.into_iter().collect::<BTreeMap<_, _>>();
    assert_storage_map_slot_entries(&storage, &slot_name, &expected);
}

#[test]
fn select_latest_account_storage_multiple_slots() {
    let mut conn = setup_test_db();
    let block_num = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_num);

    let slot_name_1 = StorageSlotName::mock(0);
    let slot_name_2 = StorageSlotName::mock(1);

    let key_a = StorageMapKey::from_index(1);
    let key_b = StorageMapKey::from_index(2);

    let value_a = Word::from([Felt::new_unchecked(11), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let value_b = Word::from([Felt::new_unchecked(22), Felt::ZERO, Felt::ZERO, Felt::ZERO]);

    let map_a = StorageMap::with_entries(vec![(key_a, value_a)]).unwrap();
    let map_b = StorageMap::with_entries(vec![(key_b, value_b)]).unwrap();

    let component_storage = vec![
        StorageSlot::with_map(slot_name_2.clone(), map_b),
        StorageSlot::with_map(slot_name_1.clone(), map_a),
    ];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "@account_procedure pub proc map push.1 end")
        .unwrap();

    let component = AccountComponent::new(
        account_component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new([9u8; 32])
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(AuthSingleSig::new(Approver::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .unwrap();

    let account_id = account.id();
    let account_commitment = account.to_commitment();
    let patch = AccountPatch::try_from(account).unwrap();
    let account_update =
        block_account_update(account_id, account_commitment, AccountUpdateDetails::Public(patch));

    upsert_accounts(
        &mut conn,
        &[account_update],
        block_num,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("upsert_accounts failed");

    let storage =
        select_latest_account_storage(&mut conn, account_id).expect("Failed to query storage");

    let expected_slot_1 = [(key_a, value_a)].into_iter().collect::<BTreeMap<_, _>>();
    let expected_slot_2 = [(key_b, value_b)].into_iter().collect::<BTreeMap<_, _>>();

    assert_storage_map_slot_entries(&storage, &slot_name_1, &expected_slot_1);
    assert_storage_map_slot_entries(&storage, &slot_name_2, &expected_slot_2);
}

#[test]
fn select_latest_account_storage_slot_updates() {
    let mut conn = setup_test_db();
    let block_1 = BlockNumber::from_epoch(0);
    let block_2 = BlockNumber::from_epoch(1);
    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);

    let slot_name = StorageSlotName::mock(0);
    let key_1 = StorageMapKey::from_index(1);
    let key_2 = StorageMapKey::from_index(2);

    let value_1 = Word::from([Felt::new_unchecked(10), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let value_2 = Word::from([Felt::new_unchecked(20), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let value_3 = Word::from([Felt::new_unchecked(30), Felt::ZERO, Felt::ZERO, Felt::ZERO]);

    let account = create_account_with_map_storage(slot_name.clone(), vec![(key_1, value_1)]);
    let account_id = account.id();
    let account_commitment = account.to_commitment();

    let patch = AccountPatch::try_from(account.clone()).unwrap();
    let account_update =
        block_account_update(account_id, account_commitment, AccountUpdateDetails::Public(patch));

    upsert_accounts(&mut conn, &[account_update], block_1, &PrecomputedPublicAccountStates::new())
        .expect("upsert_accounts failed");

    let map_patch = StorageMapPatch::from_iters([], [(key_1, value_2), (key_2, value_3)]);
    let storage_patch = AccountStoragePatch::from_raw(
        [(slot_name.clone(), StorageSlotPatch::Map(map_patch))]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap();

    let final_nonce = Felt::new_unchecked(account.nonce().as_canonical_u64() + 1);
    let partial_patch = AccountPatch::new(
        account_id,
        storage_patch,
        AccountVaultPatch::default(),
        None,
        Some(final_nonce),
    )
    .unwrap();

    let mut expected_account = account.clone();
    expected_account.apply_patch(&partial_patch).unwrap();
    let expected_commitment = expected_account.to_commitment();
    let precomputed_public_states = precomputed_states_from_account(&expected_account);

    let account_update = block_account_update(
        account_id,
        expected_commitment,
        AccountUpdateDetails::Public(partial_patch),
    );

    upsert_accounts(&mut conn, &[account_update], block_2, &precomputed_public_states)
        .expect("upsert_accounts failed");

    let storage =
        select_latest_account_storage(&mut conn, account_id).expect("Failed to query storage");

    let expected = [(key_1, value_2), (key_2, value_3)].into_iter().collect::<BTreeMap<_, _>>();
    assert_storage_map_slot_entries(&storage, &slot_name, &expected);
}

// VAULT AT BLOCK HISTORICAL QUERY TESTS
// ================================================================================================

/// Tests that querying vault at an older block returns the correct historical state,
/// even when the same `vault_key` has been updated in later blocks.
///
/// Focuses on deduplication logic that relies on ordering by (`vault_key` ASC and `block_num`
/// DESC).
#[test]
fn select_account_vault_at_block_historical_with_updates() {
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    };

    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    // Faucet ID is needed for creating FungibleAssets
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    let block_1 = BlockNumber::from_epoch(0);
    let block_2 = BlockNumber::from_epoch(1);
    let block_3 = BlockNumber::from_epoch(2);

    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);
    insert_block_header(&mut conn, block_3);

    // Insert account at block 1
    let patch = AccountPatch::try_from(account.clone()).unwrap();
    let account_update = block_account_update(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    );

    for block in [block_1, block_2, block_3] {
        upsert_accounts(
            &mut conn,
            std::slice::from_ref(&account_update),
            block,
            &precomputed_states_from_account(&account),
        )
        .expect("upsert_accounts failed");
    }

    // Insert vault asset at block 1: vault_key_1 = 1000 tokens
    let asset_v1 = Asset::from(FungibleAsset::new(faucet_id, 1000).unwrap());
    let vault_key_1 = asset_v1.id();

    insert_account_vault_asset(&mut conn, account_id, block_1, vault_key_1, Some(asset_v1))
        .expect("insert vault asset failed");

    // Update vault asset at block 2: vault_key_1 = 2000 tokens (updated value)
    let asset_v2 = Asset::from(FungibleAsset::new(faucet_id, 2000).unwrap());
    insert_account_vault_asset(&mut conn, account_id, block_2, vault_key_1, Some(asset_v2))
        .expect("insert vault asset update failed");

    // Add a second vault_key at block 2 (different faucet for different vault key)
    let faucet_id_2 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
    let asset_key2 = Asset::from(FungibleAsset::new(faucet_id_2, 500).unwrap());
    let vault_key_2 = asset_key2.id();
    insert_account_vault_asset(&mut conn, account_id, block_2, vault_key_2, Some(asset_key2))
        .expect("insert second vault asset failed");

    // Update vault_key_1 again at block 3: vault_key_1 = 3000 tokens
    let asset_v3 = Asset::from(FungibleAsset::new(faucet_id, 3000).unwrap());
    insert_account_vault_asset(&mut conn, account_id, block_3, vault_key_1, Some(asset_v3))
        .expect("insert vault asset update 2 failed");

    // Query at block 1: should only see vault_key_1 with 1000 tokens
    let assets_at_block_1 = select_account_vault_at_block(&mut conn, account_id, block_1)
        .expect("Query at block 1 should succeed");

    assert_eq!(assets_at_block_1.len(), 1, "Should have 1 asset at block 1");
    assert_eq!(assets_at_block_1[0].unwrap_fungible().amount().as_u64(), 1000);

    // Query at block 2: should see vault_key_1 with 2000 tokens AND vault_key_2 with 500 tokens
    let assets_at_block_2 = select_account_vault_at_block(&mut conn, account_id, block_2)
        .expect("Query at block 2 should succeed");

    assert_eq!(assets_at_block_2.len(), 2, "Should have 2 assets at block 2");

    // Find the amounts (order may vary)
    let amounts: Vec<u64> = assets_at_block_2
        .iter()
        .map(|asset| asset.unwrap_fungible().amount().as_u64())
        .collect();

    assert!(amounts.contains(&2000), "Block 2 should have vault_key_1 with 2000 tokens");
    assert!(amounts.contains(&500), "Block 2 should have vault_key_2 with 500 tokens");

    // Query at block 3: should see vault_key_1 with 3000 tokens AND vault_key_2 with 500 tokens
    let assets_at_block_3 = select_account_vault_at_block(&mut conn, account_id, block_3)
        .expect("Query at block 3 should succeed");

    assert_eq!(assets_at_block_3.len(), 2, "Should have 2 assets at block 3");

    let amounts: Vec<u64> = assets_at_block_3
        .iter()
        .map(|asset| asset.unwrap_fungible().amount().as_u64())
        .collect();

    assert!(amounts.contains(&3000), "Block 3 should have vault_key_1 with 3000 tokens");
    assert!(amounts.contains(&500), "Block 3 should have vault_key_2 with 500 tokens");
}

/// Tests that the query bounds the number of rows it reads, so an over-the-limit vault is detected
/// without materializing the whole set.
#[test]
fn select_account_vault_at_block_bounds_read_to_limit() {
    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    let block_1 = BlockNumber::from_epoch(0);
    insert_block_header(&mut conn, block_1);

    let patch = AccountPatch::try_from(account.clone()).unwrap();
    let account_update = block_account_update(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    );
    upsert_accounts(
        &mut conn,
        std::slice::from_ref(&account_update),
        block_1,
        &PrecomputedPublicAccountStates::new(),
    )
    .expect("upsert_accounts failed");

    // Insert two assets more than the return limit, each with a distinct vault key.
    let faucet_id = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([7; 32]);
    let asset_count = AccountVaultDetails::MAX_RETURN_ENTRIES + 2;
    for i in 0..asset_count {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![i as u8, (i >> 8) as u8]);
        let asset = Asset::from(NonFungibleAsset::new(&details));
        insert_account_vault_asset(&mut conn, account_id, block_1, asset.id(), Some(asset))
            .expect("insert vault asset failed");
    }

    // The query is capped at `MAX_RETURN_ENTRIES + 1` rows even though more assets exist, which is
    // enough for the caller to detect that the limit was exceeded.
    let assets = select_account_vault_at_block(&mut conn, account_id, block_1)
        .expect("query should succeed");
    assert_eq!(assets.len(), AccountVaultDetails::MAX_RETURN_ENTRIES + 1);
}

/// Tests that a 5-block history returns the correct asset per block.
#[test]
fn select_account_vault_at_block_exponential_updates() {
    const BLOCK_COUNT: u32 = 5;

    use miden_protocol::asset::{AssetId, FungibleAsset};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    let blocks: Vec<BlockNumber> = (0..BLOCK_COUNT).map(BlockNumber::from).collect();

    for block in &blocks {
        insert_block_header(&mut conn, *block);
    }

    let patch = AccountPatch::try_from(account.clone()).unwrap();
    let account_update = block_account_update(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    );

    for block in &blocks {
        upsert_accounts(
            &mut conn,
            std::slice::from_ref(&account_update),
            *block,
            &precomputed_states_from_account(&account),
        )
        .expect("upsert_accounts failed");
    }

    let vault_key = AssetId::new_fungible(faucet_id);

    for (index, block) in blocks.iter().enumerate() {
        let amount = 1u64 << index;
        let asset = Asset::from(FungibleAsset::new(faucet_id, amount).unwrap());
        insert_account_vault_asset(&mut conn, account_id, *block, vault_key, Some(asset))
            .expect("insert vault asset failed");
    }

    for (index, block) in blocks.iter().enumerate() {
        let assets_at_block = select_account_vault_at_block(&mut conn, account_id, *block)
            .expect("Query at block should succeed");

        assert_eq!(assets_at_block.len(), 1, "Should have 1 asset at block");
        let expected_amount = 1u64 << index;
        assert_eq!(assets_at_block[0].unwrap_fungible().amount().as_u64(), expected_amount);
    }
}

/// Tests that deleted vault assets (asset = None) are correctly excluded from results, and that the
/// deduplication handles deletion entries properly.
#[test]
fn select_account_vault_at_block_with_deletion() {
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    // Faucet ID is needed for creating FungibleAssets
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    let block_1 = BlockNumber::from_epoch(0);
    let block_2 = BlockNumber::from_epoch(1);
    let block_3 = BlockNumber::from_epoch(2);

    insert_block_header(&mut conn, block_1);
    insert_block_header(&mut conn, block_2);
    insert_block_header(&mut conn, block_3);

    // Insert account at block 1
    let patch = AccountPatch::try_from(account.clone()).unwrap();
    let account_update = block_account_update(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    );

    for block in [block_1, block_2, block_3] {
        upsert_accounts(
            &mut conn,
            std::slice::from_ref(&account_update),
            block,
            &precomputed_states_from_account(&account),
        )
        .expect("upsert_accounts failed");
    }

    // Insert vault asset at block 1
    let asset = Asset::from(FungibleAsset::new(faucet_id, 1000).unwrap());
    let vault_key = asset.id();

    insert_account_vault_asset(&mut conn, account_id, block_1, vault_key, Some(asset))
        .expect("insert vault asset failed");

    // Delete the vault asset at block 2 (insert with asset = None)
    insert_account_vault_asset(&mut conn, account_id, block_2, vault_key, None)
        .expect("delete vault asset failed");

    // Re-add the vault asset at block 3 with different amount
    let asset_v3 = Asset::from(FungibleAsset::new(faucet_id, 2000).unwrap());
    insert_account_vault_asset(&mut conn, account_id, block_3, vault_key, Some(asset_v3))
        .expect("re-add vault asset failed");

    // Query at block 1: should see the asset
    let assets_at_block_1 = select_account_vault_at_block(&mut conn, account_id, block_1)
        .expect("Query at block 1 should succeed");
    assert_eq!(assets_at_block_1.len(), 1, "Should have 1 asset at block 1");

    // Query at block 2: should NOT see the asset (it was deleted)
    let assets_at_block_2 = select_account_vault_at_block(&mut conn, account_id, block_2)
        .expect("Query at block 2 should succeed");
    assert!(assets_at_block_2.is_empty(), "Should have no assets at block 2 (deleted)");

    // Query at block 3: should see the re-added asset with new amount
    let assets_at_block_3 = select_account_vault_at_block(&mut conn, account_id, block_3)
        .expect("Query at block 3 should succeed");
    assert_eq!(assets_at_block_3.len(), 1, "Should have 1 asset at block 3");
    assert_eq!(assets_at_block_3[0].unwrap_fungible().amount().as_u64(), 2000);
}

// ACCOUNT CODE PRUNING TESTS
// ================================================================================================

/// Counts the number of rows in `account_codes`.
fn count_account_codes(conn: &mut SqliteConnection) -> usize {
    use schema::account_codes;

    let val =
        SelectDsl::select(account_codes::table, diesel::dsl::count(account_codes::code_commitment))
            .get_result::<i64>(conn)
            .expect("Failed to count account_codes");
    usize::try_from(u64::try_from(val).unwrap()).unwrap()
}

/// Returns whether a specific code commitment exists in `account_codes`.
fn account_code_exists(conn: &mut SqliteConnection, code_commitment: Word) -> bool {
    use schema::account_codes;

    let n =
        SelectDsl::select(account_codes::table, diesel::dsl::count(account_codes::code_commitment))
            .filter(account_codes::code_commitment.eq(code_commitment.to_bytes()))
            .get_result::<i64>(conn)
            .expect("Failed to query account_codes");

    n == 1
}

/// Creates a full-state [`BlockAccountUpdate`] for the given account.
fn make_full_state_update(account: &Account) -> BlockAccountUpdate {
    let patch = AccountPatch::try_from(account.clone()).unwrap();
    assert!(patch.is_full_state(), "expected full-state patch");
    block_account_update(account.id(), account.to_commitment(), AccountUpdateDetails::Public(patch))
}

/// Builds a public account using a fixed account ID seed but a different component code.
///
/// All accounts produced here share the same [`AccountId`] because the same seed is used.
/// The `push_value` must be different for each variant to produce a distinct MAST root and thus a
/// distinct [`AccountCode::commitment`].
fn build_account_with_code(push_value: u32) -> Account {
    // The seed alone determines the account ID, so every `push_value` variant maps to the same
    // account — the property the prune tests rely on to model one account changing its code.
    // Keeping the seed distinct from the other helpers' ([1u8; 32], [9u8; 32], ...) is only a
    // precaution: each test runs on a fresh database, so a collision would matter only if a single
    // test mixed this helper with another one.
    build_account_with_code_seeded(push_value, [2u8; 32])
}

/// Same as [`build_account_with_code`] but with a caller-chosen ID seed, for tests that need
/// multiple distinct accounts sharing the same code.
fn build_account_with_code_seeded(push_value: u32, seed: [u8; 32]) -> Account {
    let code_src = format!("@account_procedure pub proc variant push.{push_value} end");
    let component_code = CodeBuilder::default()
        .compile_component_code("test::code_prune", &code_src)
        .unwrap();
    let component = AccountComponent::new(
        component_code,
        vec![StorageSlot::with_value(
            StorageSlotName::mock(0),
            Word::from([Felt::new_unchecked(1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        )],
        AccountComponentMetadata::new("code_prune_test"),
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

/// Prune test 2: when an account's code changes, the old code must be pruned after the retention
/// window, while the new (latest) code is retained.
#[test]
fn prune_account_code_retains_latest_after_code_change() {
    let mut conn = setup_test_db();

    // Block 0: account created with code A.
    // Block RETENTION+1 (=51): account updated to code B — within the retention window at prune
    //   time.
    // Block 2*RETENTION+1 (=101): prune → cutoff is block 51; code A (last at block 0) is outside
    //   the window → pruned; code B (last at block 51) is within the window → retained.
    let block_0 = BlockNumber::from(0u32);
    let block_code_b = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 1);
    let block_prunable = BlockNumber::from(2 * HISTORICAL_BLOCK_RETENTION + 1);

    insert_block_header(&mut conn, block_0);
    insert_block_header(&mut conn, block_code_b);
    insert_block_header(&mut conn, block_prunable);

    let account_a = build_account_with_code(1);
    let account_b = build_account_with_code(2);

    // Both accounts must have the same ID for this to test code replacement.
    assert_eq!(account_a.id(), account_b.id(), "accounts must share the same ID");
    assert_ne!(
        account_a.code().commitment(),
        account_b.code().commitment(),
        "accounts must have different codes"
    );

    let account_id = account_a.id();
    let code_commitment_a = account_a.code().commitment();
    let code_commitment_b = account_b.code().commitment();

    // Block 0: insert account with code A.
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_a)],
        block_0,
        &precomputed_states_from_account(&account_a),
    )
    .expect("initial upsert failed");

    // Block RETENTION+1: update the same account ID to code B via a full-state delta.
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_b)],
        block_code_b,
        &precomputed_states_from_account(&account_b),
    )
    .expect("code-change upsert failed");

    assert_eq!(count_account_codes(&mut conn), 2, "both codes must exist before pruning");

    // Advance past retention window and prune. cutoff = block_prunable - RETENTION = 2*RETENTION+1
    // - RETENTION = RETENTION+1 = block_code_b
    let (_, _, codes_deleted) =
        prune_history(&mut conn, block_prunable).expect("prune_history failed");

    // Only code A was dropped; code B is still referenced by the latest accounts row.
    assert_eq!(codes_deleted, 1, "exactly one code (A) must be pruned");
    assert!(!account_code_exists(&mut conn, code_commitment_a), "old code A must be pruned");
    assert!(
        account_code_exists(&mut conn, code_commitment_b),
        "current code B must be retained"
    );

    // Confirm the latest account row still points to code B.
    let (latest_header, _) =
        select_account_header_with_storage_header_at_block(&mut conn, account_id, block_prunable)
            .expect("query failed")
            .expect("account must still exist");
    assert_eq!(
        latest_header.code_commitment(),
        account_b.code().commitment(),
        "latest account must reference code B"
    );
}

/// Prune test 3: code A → code B → code A; after the retention window, code B must be pruned but
/// code A must be retained because it is still the latest.
#[test]
fn prune_account_code_retains_revisited_code() {
    let mut conn = setup_test_db();

    // Block 0:           code A.
    // Block RETENTION+1: code B (will be outside retention window at prune time).
    // Block RETENTION+2: back to code A (within the retention window at prune time).
    // Block 2*RETENTION+2: prune.
    //   cutoff = 2*RETENTION+2 - RETENTION = RETENTION+2.
    //   Code A: last referenced at block RETENTION+2 >= cutoff → retained.
    //   Code B: last referenced at block RETENTION+1 < cutoff → pruned.
    let block_0 = BlockNumber::from(0u32);
    let block_code_b = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 1);
    let block_code_a_again = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 2);
    let block_prunable = BlockNumber::from(2 * HISTORICAL_BLOCK_RETENTION + 2);

    insert_block_header(&mut conn, block_0);
    insert_block_header(&mut conn, block_code_b);
    insert_block_header(&mut conn, block_code_a_again);
    insert_block_header(&mut conn, block_prunable);

    let account_a = build_account_with_code(1);
    let account_b = build_account_with_code(2);

    assert_eq!(account_a.id(), account_b.id(), "accounts must share the same ID");
    assert_ne!(
        account_a.code().commitment(),
        account_b.code().commitment(),
        "accounts must have different codes"
    );

    let account_id = account_a.id();
    let code_commitment_a = account_a.code().commitment();
    let code_commitment_b = account_b.code().commitment();

    // Block 0: code A.
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_a)],
        block_0,
        &precomputed_states_from_account(&account_a),
    )
    .expect("block 0 upsert failed");
    // Block RETENTION+1: code B.
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_b)],
        block_code_b,
        &precomputed_states_from_account(&account_b),
    )
    .expect("block code_b upsert failed");
    // Block RETENTION+2: back to code A.
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_a)],
        block_code_a_again,
        &precomputed_states_from_account(&account_a),
    )
    .expect("block code_a_again upsert failed");

    // Before pruning: both codes must be in account_codes (code A inserted once via ON CONFLICT DO
    // NOTHING, code B inserted once).
    assert_eq!(count_account_codes(&mut conn), 2, "both codes must exist before pruning");

    // Advance past retention window and prune.
    let (_, _, codes_deleted) =
        prune_history(&mut conn, block_prunable).expect("prune_history failed");

    // Code B is no longer referenced by any account row within the retention window → pruned. Code
    // A is still referenced by the block_code_a_again accounts row (within cutoff) → retained.
    assert_eq!(codes_deleted, 1, "exactly one code (B) must be pruned");
    assert!(account_code_exists(&mut conn, code_commitment_a), "code A must be retained");
    assert!(!account_code_exists(&mut conn, code_commitment_b), "code B must be pruned");

    // Confirm the latest account row still points to code A.
    let (latest_header, _) =
        select_account_header_with_storage_header_at_block(&mut conn, account_id, block_prunable)
            .expect("query failed")
            .expect("account must still exist");
    assert_eq!(
        latest_header.code_commitment(),
        account_a.code().commitment(),
        "latest account must reference code A"
    );
}

/// Prune test 4: a code referenced only by an account's baseline row — the newest row below the
/// cutoff — must be retained, because that row is still the applicable state for in-window blocks
/// preceding the account's first in-window update. Once a newer row falls below the cutoff, the
/// code becomes prunable.
#[test]
fn prune_account_code_retains_baseline_code() {
    let mut conn = setup_test_db();

    // Block 0:             code A.
    // Block 2*RETENTION:   code B.
    // Block 2*RETENTION+1: prune → cutoff = RETENTION+1.
    //   Code A's row (block 0) is the account's newest row below the cutoff: reads at any block in
    //   [cutoff, 2*RETENTION) resolve to it, so code A must be retained.
    // Block 3*RETENTION+1: prune → cutoff = 2*RETENTION+1.
    //   The code-B row (block 2*RETENTION) is now the baseline, so code A becomes prunable.
    let block_0 = BlockNumber::from(0u32);
    let block_code_b = BlockNumber::from(2 * HISTORICAL_BLOCK_RETENTION);
    let block_first_prune = BlockNumber::from(2 * HISTORICAL_BLOCK_RETENTION + 1);
    let block_second_prune = BlockNumber::from(3 * HISTORICAL_BLOCK_RETENTION + 1);

    insert_block_header(&mut conn, block_0);
    insert_block_header(&mut conn, block_code_b);
    insert_block_header(&mut conn, block_first_prune);
    insert_block_header(&mut conn, block_second_prune);

    let account_a = build_account_with_code(1);
    let account_b = build_account_with_code(2);

    assert_eq!(account_a.id(), account_b.id(), "accounts must share the same ID");

    let code_commitment_a = account_a.code().commitment();
    let code_commitment_b = account_b.code().commitment();

    // Block 0: code A.
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_a)],
        block_0,
        &precomputed_states_from_account(&account_a),
    )
    .expect("block 0 upsert failed");
    // Block 2*RETENTION: code B.
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_b)],
        block_code_b,
        &precomputed_states_from_account(&account_b),
    )
    .expect("code-change upsert failed");

    assert_eq!(count_account_codes(&mut conn), 2, "both codes must exist before pruning");

    // First prune: the block-0 row is the baseline (its successor is above the cutoff), so code A
    // must survive.
    let (_, _, codes_deleted) =
        prune_history(&mut conn, block_first_prune).expect("prune_history failed");
    assert_eq!(codes_deleted, 0, "no code may be pruned while code A backs the baseline row");
    assert!(
        account_code_exists(&mut conn, code_commitment_a),
        "baseline code A must be retained"
    );
    assert!(
        account_code_exists(&mut conn, code_commitment_b),
        "current code B must be retained"
    );

    // Second prune: the code-B row is now at or below the cutoff and supersedes the block-0 row, so
    // code A is no longer reachable from any in-window read.
    let (_, _, codes_deleted) =
        prune_history(&mut conn, block_second_prune).expect("prune_history failed");
    assert_eq!(codes_deleted, 1, "exactly one code (A) must be pruned");
    assert!(!account_code_exists(&mut conn, code_commitment_a), "old code A must be pruned");
    assert!(
        account_code_exists(&mut conn, code_commitment_b),
        "current code B must be retained"
    );
}

/// Returns the cutoff recorded in `prune_progress`, if any.
fn codes_prune_cutoff(conn: &mut SqliteConnection) -> Option<i64> {
    SelectDsl::select(schema::prune_progress::table, schema::prune_progress::codes_cutoff)
        .first(conn)
        .optional()
        .expect("Failed to query prune_progress")
}

/// Prune test 5: the incremental (windowed) codes prune must not delete a code whose expiring
/// reference crosses the cutoff window while another account still references it, and must delete
/// it once the last reference expires in a later window.
#[test]
fn prune_account_code_incremental_cross_account_reference() {
    let mut conn = setup_test_db();

    // The "switcher" account changes code first; the "holdout" account keeps code A pinned.
    // Both accounts are created with code A at block 0.
    // Prune 1 (tip 2R+1 → cutoff R+1): no marker yet, full pass; nothing is collectable.
    // Block 2R+2: the switcher moves to code B — its code-A row expires at 2R+2.
    // Prune 2 (tip 3R+2 → cutoff 2R+2): the expired row crosses the window `(R+1, 2R+2]`, making
    //   code A a candidate, but the holdout's open row still references it → retained.
    // Block 3R+3: the holdout moves to code B — its code-A row expires at 3R+3.
    // Prune 3 (tip 4R+3 → cutoff 3R+3): code A is a candidate again and no row references it past
    //   the cutoff → pruned. Code B is retained.
    let block_0 = BlockNumber::from(0u32);
    let block_first_prune = BlockNumber::from(2 * HISTORICAL_BLOCK_RETENTION + 1);
    let block_switcher_to_b = BlockNumber::from(2 * HISTORICAL_BLOCK_RETENTION + 2);
    let block_second_prune = BlockNumber::from(3 * HISTORICAL_BLOCK_RETENTION + 2);
    let block_holdout_to_b = BlockNumber::from(3 * HISTORICAL_BLOCK_RETENTION + 3);
    let block_third_prune = BlockNumber::from(4 * HISTORICAL_BLOCK_RETENTION + 3);

    for block in [block_0, block_switcher_to_b, block_holdout_to_b] {
        insert_block_header(&mut conn, block);
    }

    let switcher_on_a = build_account_with_code(1);
    let switcher_on_b = build_account_with_code(2);
    let holdout_on_a = build_account_with_code_seeded(1, [4u8; 32]);
    let holdout_on_b = build_account_with_code_seeded(2, [4u8; 32]);

    assert_ne!(switcher_on_a.id(), holdout_on_a.id(), "accounts must be distinct");
    let code_commitment_a = switcher_on_a.code().commitment();
    let code_commitment_b = switcher_on_b.code().commitment();
    assert_eq!(
        code_commitment_a,
        holdout_on_a.code().commitment(),
        "both accounts must share code A"
    );

    for account in [&switcher_on_a, &holdout_on_a] {
        upsert_accounts(
            &mut conn,
            &[make_full_state_update(account)],
            block_0,
            &precomputed_states_from_account(account),
        )
        .expect("block 0 upsert failed");
    }

    let (_, _, codes_deleted) =
        prune_history(&mut conn, block_first_prune).expect("prune_history failed");
    assert_eq!(codes_deleted, 0, "no code is collectable while both accounts run code A");

    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&switcher_on_b)],
        block_switcher_to_b,
        &precomputed_states_from_account(&switcher_on_b),
    )
    .expect("switcher code-change upsert failed");

    let (_, _, codes_deleted) =
        prune_history(&mut conn, block_second_prune).expect("prune_history failed");
    assert_eq!(codes_deleted, 0, "code A must survive while the holdout still references it");
    assert!(
        account_code_exists(&mut conn, code_commitment_a),
        "code A must be retained while the holdout references it"
    );

    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&holdout_on_b)],
        block_holdout_to_b,
        &precomputed_states_from_account(&holdout_on_b),
    )
    .expect("holdout code-change upsert failed");

    let (_, _, codes_deleted) =
        prune_history(&mut conn, block_third_prune).expect("prune_history failed");
    assert_eq!(codes_deleted, 1, "exactly one code (A) must be pruned");
    assert!(!account_code_exists(&mut conn, code_commitment_a), "code A must be pruned");
    assert!(
        account_code_exists(&mut conn, code_commitment_b),
        "current code B must be retained"
    );
}

/// Prune test 6: `prune_progress` records the cutoff of the last codes prune; re-pruning at the
/// same or a lower cutoff deletes nothing and never moves the marker backwards.
#[test]
fn prune_account_codes_marker_never_regresses() {
    let mut conn = setup_test_db();

    // Same shape as prune test 2: code A at block 0 is superseded by code B at block R+1, so a
    // prune at tip 2R+1 (cutoff R+1) collects code A.
    let block_0 = BlockNumber::from(0u32);
    let block_code_b = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 1);
    let block_prune = BlockNumber::from(2 * HISTORICAL_BLOCK_RETENTION + 1);

    insert_block_header(&mut conn, block_0);
    insert_block_header(&mut conn, block_code_b);

    let account_a = build_account_with_code(1);
    let account_b = build_account_with_code(2);

    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_a)],
        block_0,
        &precomputed_states_from_account(&account_a),
    )
    .expect("block 0 upsert failed");
    upsert_accounts(
        &mut conn,
        &[make_full_state_update(&account_b)],
        block_code_b,
        &precomputed_states_from_account(&account_b),
    )
    .expect("code-change upsert failed");

    assert_eq!(codes_prune_cutoff(&mut conn), None, "no marker before the first prune");

    let cutoff = i64::from(HISTORICAL_BLOCK_RETENTION + 1);
    let (_, _, codes_deleted) = prune_history(&mut conn, block_prune).expect("first prune failed");
    assert_eq!(codes_deleted, 1, "exactly one code (A) must be pruned");
    assert_eq!(codes_prune_cutoff(&mut conn), Some(cutoff), "marker must record the cutoff");

    // Re-pruning at the same tip is a no-op.
    let (_, _, codes_deleted) = prune_history(&mut conn, block_prune).expect("second prune failed");
    assert_eq!(codes_deleted, 0, "re-pruning at the same cutoff must delete nothing");
    assert_eq!(codes_prune_cutoff(&mut conn), Some(cutoff), "marker must be unchanged");

    // Pruning at a lower tip (cutoff 0) must not move the marker backwards.
    let (_, _, codes_deleted) =
        prune_history(&mut conn, BlockNumber::from(HISTORICAL_BLOCK_RETENTION))
            .expect("stale prune failed");
    assert_eq!(codes_deleted, 0, "pruning below the marker must delete nothing");
    assert_eq!(codes_prune_cutoff(&mut conn), Some(cutoff), "marker must never regress");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn network_accounts_subset_classifies_correctly() {
    use crate::db::models::queries::accounts::{
        AccountRowInsert,
        NetworkAccountType,
        select_network_accounts_subset,
    };

    let mut conn = setup_test_db();
    let block_num = BlockNumber::from(1);
    insert_block_header(&mut conn, block_num);

    // Three accounts with distinct classifications. AccountIds are dummies — the queries only care
    // about the (account_id, network_account_type, valid_until) tuple, not protocol-level validity.
    let network_id = AccountId::dummy(
        [1u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    let public_id = AccountId::dummy(
        [2u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    let private_id = AccountId::dummy(
        [3u8; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );
    let unknown_id = AccountId::dummy(
        [4u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );

    for (id, ty) in [
        (network_id, NetworkAccountType::Network),
        (public_id, NetworkAccountType::None),
        (private_id, NetworkAccountType::None),
    ] {
        let row = AccountRowInsert::new_private(id, ty, Word::default(), block_num, block_num);
        diesel::insert_into(crate::db::schema::accounts::table)
            .values(&row)
            .execute(&mut conn)
            .unwrap();
    }

    // Batched lookup returns only the network-classified id; public, private, and unknown ids are
    // all omitted.
    let subset =
        select_network_accounts_subset(&mut conn, &[network_id, public_id, private_id, unknown_id])
            .unwrap();
    assert_eq!(subset.len(), 1);
    assert!(subset.contains(&network_id));

    // Empty input slice short-circuits to an empty result.
    let empty = select_network_accounts_subset(&mut conn, &[]).unwrap();
    assert!(empty.is_empty());
}
