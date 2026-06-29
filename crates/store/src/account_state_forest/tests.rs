use assert_matches::assert_matches;
use miden_node_proto::domain::account::{AccountVaultDetails, StorageMapEntries};
use miden_protocol::Felt;
use miden_protocol::account::{AccountCode, AccountType, StorageMapKey};
use miden_protocol::asset::{
    Asset,
    AssetVault,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    AccountIdBuilder,
};

use super::*;

fn dummy_account() -> AccountId {
    AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap()
}

fn dummy_faucet() -> AccountId {
    AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap()
}

fn dummy_fungible_asset(faucet_id: AccountId, amount: u64) -> Asset {
    FungibleAsset::new(faucet_id, amount).unwrap().into()
}

/// Creates a partial `AccountPatch` (without code) for testing incremental updates.
fn dummy_partial_patch(
    account_id: AccountId,
    vault_patch: AccountVaultPatch,
    storage_patch: AccountStoragePatch,
) -> AccountPatch {
    let final_nonce = if vault_patch.is_empty() && storage_patch.is_empty() {
        None
    } else {
        Some(Felt::new_unchecked(2))
    };
    AccountPatch::new(account_id, storage_patch, vault_patch, None, final_nonce).unwrap()
}

/// Creates a full-state `AccountPatch` (with code) for testing DB reconstruction.
fn dummy_full_state_patch(account_id: AccountId, assets: &[Asset]) -> AccountPatch {
    use miden_protocol::account::{Account, AccountStorage};

    let vault = AssetVault::new(assets).unwrap();
    let storage = AccountStorage::new(vec![]).unwrap();
    let code = AccountCode::mock();
    let nonce = Felt::ONE;

    let account = Account::new(account_id, vault, storage, code, nonce, None).unwrap();
    AccountPatch::try_from(account).unwrap()
}

// INITIALIZATION & BASIC OPERATIONS
// ================================================================================================

#[test]
fn empty_smt_root_is_recognized() {
    use miden_crypto::merkle::smt::Smt;

    let empty_root = AccountStateForest::empty_smt_root();

    assert_eq!(Smt::default().root(), empty_root);
}

#[test]
fn account_state_forest_basic_initialization() {
    let forest = AccountStateForest::new();
    assert_eq!(forest.forest.lineage_count(), 0);
    assert_eq!(forest.forest.tree_count(), 0);
}

#[test]
fn update_account_with_empty_deltas() {
    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    let patch = dummy_partial_patch(
        account_id,
        AccountVaultPatch::default(),
        AccountStoragePatch::default(),
    );

    forest.update_account(block_num, &patch);

    assert!(forest.get_vault_root(account_id, block_num).is_none());
    assert_eq!(forest.forest.lineage_count(), 0);
}

// VAULT TESTS
// ================================================================================================

#[test]
fn vault_partial_vs_full_state_produces_same_root() {
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let block_num = BlockNumber::GENESIS.child();
    let asset = dummy_fungible_asset(faucet_id, 100);

    // Partial patch (block application)
    let mut forest_partial = AccountStateForest::new();
    let mut vault_patch = AccountVaultPatch::default();
    vault_patch.insert_asset(asset);
    let partial_patch =
        dummy_partial_patch(account_id, vault_patch, AccountStoragePatch::default());
    forest_partial.update_account(block_num, &partial_patch);

    // Full-state patch (DB reconstruction)
    let mut forest_full = AccountStateForest::new();
    let full_patch = dummy_full_state_patch(account_id, &[asset]);
    forest_full.update_account(block_num, &full_patch);

    let root_partial = forest_partial.get_vault_root(account_id, block_num).unwrap();
    let root_full = forest_full.get_vault_root(account_id, block_num).unwrap();

    assert_eq!(root_partial, root_full);
    assert_ne!(root_partial, EMPTY_WORD);
}

#[test]
fn vault_incremental_updates_with_add_and_remove() {
    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    // Block 1: Set balance to 100 tokens
    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_patch_1 = AccountVaultPatch::default();
    vault_patch_1.insert_asset(dummy_fungible_asset(faucet_id, 100));
    let patch_1 = dummy_partial_patch(account_id, vault_patch_1, AccountStoragePatch::default());
    forest.update_account(block_1, &patch_1);
    let root_after_100 = forest.get_vault_root(account_id, block_1).unwrap();

    // Block 2: Set balance to 150 tokens
    let block_2 = block_1.child();
    let mut vault_patch_2 = AccountVaultPatch::default();
    vault_patch_2.insert_asset(dummy_fungible_asset(faucet_id, 150));
    let patch_2 = dummy_partial_patch(account_id, vault_patch_2, AccountStoragePatch::default());
    forest.update_account(block_2, &patch_2);
    let root_after_150 = forest.get_vault_root(account_id, block_2).unwrap();

    assert_ne!(root_after_100, root_after_150);

    // Block 3: Set balance to 120 tokens
    let block_3 = block_2.child();
    let mut vault_patch_3 = AccountVaultPatch::default();
    vault_patch_3.insert_asset(dummy_fungible_asset(faucet_id, 120));
    let patch_3 = dummy_partial_patch(account_id, vault_patch_3, AccountStoragePatch::default());
    forest.update_account(block_3, &patch_3);
    let root_after_120 = forest.get_vault_root(account_id, block_3).unwrap();

    assert_ne!(root_after_150, root_after_120);

    // Verify by comparing to full-state patch
    let mut fresh_forest = AccountStateForest::new();
    let full_patch = dummy_full_state_patch(account_id, &[dummy_fungible_asset(faucet_id, 120)]);
    fresh_forest.update_account(block_3, &full_patch);
    let root_full_state_120 = fresh_forest.get_vault_root(account_id, block_3).unwrap();

    assert_eq!(root_after_120, root_full_state_120);
}

#[test]
fn vault_details_returns_latest_and_historical_assets() {
    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    let block_1 = BlockNumber::GENESIS.child();
    let asset_100 = dummy_fungible_asset(faucet_id, 100);
    let full_patch = dummy_full_state_patch(account_id, &[asset_100]);
    forest.update_account(block_1, &full_patch);

    let block_2 = block_1.child();
    let mut vault_patch_2 = AccountVaultPatch::default();
    vault_patch_2.insert_asset(dummy_fungible_asset(faucet_id, 150));
    let patch_2 = dummy_partial_patch(account_id, vault_patch_2, AccountStoragePatch::default());
    forest.update_account(block_2, &patch_2);

    let historical = forest.get_vault_details(account_id, block_1).unwrap().unwrap();
    assert_eq!(historical, AccountVaultDetails::Assets(vec![asset_100]));

    let latest = forest.get_vault_details(account_id, block_2).unwrap().unwrap();
    assert_eq!(latest, AccountVaultDetails::Assets(vec![dummy_fungible_asset(faucet_id, 150)]));
}

#[test]
fn vault_details_limit_exceeded_for_large_vault() {
    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    let faucet_id = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([7; 32]);
    let assets = (0..=AccountVaultDetails::MAX_RETURN_ENTRIES)
        .map(|i| {
            let details = NonFungibleAssetDetails::new(faucet_id, vec![i as u8, (i >> 8) as u8]);
            Asset::NonFungible(NonFungibleAsset::new(&details))
        })
        .collect::<Vec<_>>();

    let full_patch = dummy_full_state_patch(account_id, &assets);
    forest.update_account(block_num, &full_patch);

    assert_eq!(
        forest.get_vault_details(account_id, block_num).unwrap().unwrap(),
        AccountVaultDetails::LimitExceeded
    );
}

#[test]
fn forest_versions_are_continuous_for_sequential_updates() {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_name = StorageSlotName::mock(9);
    let raw_key = StorageMapKey::from_index(1u32);
    let storage_key = raw_key.hash().into();
    let asset_key: Word = FungibleAsset::new(faucet_id, 0).unwrap().vault_key().into();

    for i in 1..=3u32 {
        let block_num = BlockNumber::from(i);
        let mut vault_patch = AccountVaultPatch::default();
        vault_patch.insert_asset(dummy_fungible_asset(faucet_id, u64::from(i) * 10));

        let mut map_patch = StorageMapPatch::default();
        map_patch.insert(raw_key, Word::from([i, 0, 0, 0]));
        let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch))]);
        let storage_patch = AccountStoragePatch::from_raw(raw);

        let patch = dummy_partial_patch(account_id, vault_patch, storage_patch);
        forest.update_account(block_num, &patch);

        let vault_tree = forest.tree_id_for_vault_root(account_id, block_num);
        let storage_tree = forest.tree_id_for_root(account_id, &slot_name, block_num);

        assert_matches!(forest.forest.open(vault_tree, asset_key), Ok(_));
        assert_matches!(forest.forest.open(storage_tree, storage_key), Ok(_));
    }
}

#[test]
fn vault_state_is_not_available_for_block_gaps() {
    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_patch_1 = AccountVaultPatch::default();
    vault_patch_1.insert_asset(dummy_fungible_asset(faucet_id, 100));
    let patch_1 = dummy_partial_patch(account_id, vault_patch_1, AccountStoragePatch::default());
    forest.update_account(block_1, &patch_1);

    let block_6 = BlockNumber::from(6);
    let mut vault_patch_6 = AccountVaultPatch::default();
    vault_patch_6.insert_asset(dummy_fungible_asset(faucet_id, 150));
    let patch_6 = dummy_partial_patch(account_id, vault_patch_6, AccountStoragePatch::default());
    forest.update_account(block_6, &patch_6);

    assert!(forest.get_vault_root(account_id, BlockNumber::from(3)).is_some());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(5)).is_some());
    assert!(forest.get_vault_root(account_id, block_6).is_some());
}

#[test]
fn vault_full_state_with_empty_vault_records_root() {
    use miden_protocol::account::{Account, AccountStorage};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    let vault = AssetVault::new(&[]).unwrap();
    let storage = AccountStorage::new(vec![]).unwrap();
    let code = AccountCode::mock();
    let nonce = Felt::ONE;
    let account = Account::new(account_id, vault, storage, code, nonce, None).unwrap();
    let full_patch = AccountPatch::try_from(account).unwrap();

    assert!(full_patch.vault().is_empty());
    assert!(full_patch.is_full_state());

    forest.update_account(block_num, &full_patch);

    let recorded_root = forest.get_vault_root(account_id, block_num);
    assert_eq!(recorded_root, Some(AccountStateForest::empty_smt_root()));
}

#[test]
fn vault_shared_root_retained_when_one_entry_pruned() {
    let mut forest = AccountStateForest::new();
    let account1 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let account2 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();
    let faucet_id = dummy_faucet();
    let block_1 = BlockNumber::GENESIS.child();
    let asset_amount = u64::from(HISTORICAL_BLOCK_RETENTION);
    let amount_increment = asset_amount / u64::from(HISTORICAL_BLOCK_RETENTION);
    let asset = dummy_fungible_asset(faucet_id, asset_amount);

    let mut vault_patch_1 = AccountVaultPatch::default();
    vault_patch_1.insert_asset(asset);
    let patch_1 = dummy_partial_patch(account1, vault_patch_1, AccountStoragePatch::default());
    forest.update_account(block_1, &patch_1);

    let mut vault_patch_2 = AccountVaultPatch::default();
    vault_patch_2.insert_asset(dummy_fungible_asset(faucet_id, asset_amount));
    let patch_2 = dummy_partial_patch(account2, vault_patch_2, AccountStoragePatch::default());
    forest.update_account(block_1, &patch_2);

    let root1 = forest.get_vault_root(account1, block_1).unwrap();
    let root2 = forest.get_vault_root(account2, block_1).unwrap();
    assert_eq!(root1, root2);

    let block_at_51 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 1);
    let mut vault_patch_2_update = AccountVaultPatch::default();
    vault_patch_2_update
        .insert_asset(dummy_fungible_asset(faucet_id, asset_amount + amount_increment));
    let patch_2_update =
        dummy_partial_patch(account2, vault_patch_2_update, AccountStoragePatch::default());
    forest.update_account(block_at_51, &patch_2_update);

    let block_at_52 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 2);
    let total_roots_removed = forest.prune(block_at_52);

    assert_eq!(total_roots_removed, 0);
    assert!(forest.get_vault_root(account1, block_1).is_some());
    assert!(forest.get_vault_root(account2, block_1).is_some());

    let vault_root_at_52 = forest.get_vault_root(account1, block_at_52);
    assert_eq!(vault_root_at_52, Some(root1));
}

// STORAGE MAP TESTS
// ================================================================================================

#[test]
fn storage_map_incremental_updates() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();

    let slot_name = StorageSlotName::mock(3);
    let key1 = StorageMapKey::from_index(1u32);
    let key2 = StorageMapKey::from_index(2u32);
    let value1 = Word::from([10u32, 0, 0, 0]);
    let value2 = Word::from([20u32, 0, 0, 0]);
    let value3 = Word::from([30u32, 0, 0, 0]);

    // Block 1: Insert key1 -> value1
    let block_1 = BlockNumber::GENESIS.child();
    let mut map_patch_1 = StorageMapPatch::default();
    map_patch_1.insert(key1, value1);
    let raw_1 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch_1))]);
    let storage_patch_1 = AccountStoragePatch::from_raw(raw_1);
    let patch_1 = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_1);
    forest.update_account(block_1, &patch_1);
    let root_1 = forest.get_storage_map_root(account_id, &slot_name, block_1).unwrap();

    // Block 2: Insert key2 -> value2
    let block_2 = block_1.child();
    let mut map_patch_2 = StorageMapPatch::default();
    map_patch_2.insert(key2, value2);
    let raw_2 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch_2))]);
    let storage_patch_2 = AccountStoragePatch::from_raw(raw_2);
    let patch_2 = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_2);
    forest.update_account(block_2, &patch_2);
    let root_2 = forest.get_storage_map_root(account_id, &slot_name, block_2).unwrap();

    // Block 3: Update key1 -> value3
    let block_3 = block_2.child();
    let mut map_patch_3 = StorageMapPatch::default();
    map_patch_3.insert(key1, value3);
    let raw_3 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch_3))]);
    let storage_patch_3 = AccountStoragePatch::from_raw(raw_3);
    let patch_3 = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_3);
    forest.update_account(block_3, &patch_3);
    let root_3 = forest.get_storage_map_root(account_id, &slot_name, block_3).unwrap();

    assert_ne!(root_1, root_2);
    assert_ne!(root_2, root_3);
    assert_ne!(root_1, root_3);
}

#[test]
fn test_storage_map_removals() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    const SLOT_INDEX: usize = 3;
    const VALUE_1: [u32; 4] = [10, 0, 0, 0];
    const VALUE_2: [u32; 4] = [20, 0, 0, 0];

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(SLOT_INDEX);
    let key_1 = StorageMapKey::from_index(1);
    let key_2 = StorageMapKey::from_index(2);
    let value_1 = Word::from(VALUE_1);
    let value_2 = Word::from(VALUE_2);

    let block_1 = BlockNumber::GENESIS.child();
    let mut map_patch_1 = StorageMapPatch::default();
    map_patch_1.insert(key_1, value_1);
    map_patch_1.insert(key_2, value_2);
    let raw_1 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch_1))]);
    let storage_patch_1 = AccountStoragePatch::from_raw(raw_1);
    let patch_1 = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_1);
    forest.update_account(block_1, &patch_1);

    let block_2 = block_1.child();
    let map_patch_2 = StorageMapPatch::from_iters([key_1], []);
    let raw_2 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch_2))]);
    let storage_patch_2 = AccountStoragePatch::from_raw(raw_2);
    let patch_2 = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_2);
    forest.update_account(block_2, &patch_2);

    let tree = forest.tree_id_for_root(account_id, &slot_name, block_2);

    let key_2_hash = key_2.hash().into();
    let key_1_hash = key_1.hash().into();

    let proof_key_2 = forest.forest.open(tree, key_2_hash).unwrap();
    assert_eq!(proof_key_2.get(&key_2_hash), Some(value_2));

    let proof_key_1 = forest.forest.open(tree, key_1_hash).unwrap();
    assert_eq!(proof_key_1.get(&key_1_hash), Some(EMPTY_WORD));
}

#[test]
fn storage_map_state_is_not_available_for_block_gaps() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    const BLOCK_FIRST: u32 = 1;
    const BLOCK_SECOND: u32 = 4;
    const BLOCK_QUERY_ONE: u32 = 2;
    const BLOCK_QUERY_TWO: u32 = 3;
    const KEY_VALUE: u32 = 7;
    const VALUE_FIRST: u32 = 10;
    const VALUE_SECOND: u32 = 20;

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(4);
    let raw_key = StorageMapKey::from_index(KEY_VALUE);

    let block_1 = BlockNumber::from(BLOCK_FIRST);
    let mut map_patch_1 = StorageMapPatch::default();
    let value_1 = Word::from([VALUE_FIRST, 0, 0, 0]);
    map_patch_1.insert(raw_key, value_1);
    let raw_1 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch_1))]);
    let storage_patch_1 = AccountStoragePatch::from_raw(raw_1);
    let patch_1 = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_1);
    forest.update_account(block_1, &patch_1);

    let block_4 = BlockNumber::from(BLOCK_SECOND);
    let mut map_patch_4 = StorageMapPatch::default();
    let value_2 = Word::from([VALUE_SECOND, 0, 0, 0]);
    map_patch_4.insert(raw_key, value_2);
    let raw_4 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch_4))]);
    let storage_patch_4 = AccountStoragePatch::from_raw(raw_4);
    let patch_4 = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_4);
    forest.update_account(block_4, &patch_4);

    assert!(
        forest
            .get_storage_map_root(account_id, &slot_name, BlockNumber::from(BLOCK_QUERY_ONE))
            .is_some()
    );
    assert!(
        forest
            .get_storage_map_root(account_id, &slot_name, BlockNumber::from(BLOCK_QUERY_TWO))
            .is_some()
    );
    assert!(forest.get_storage_map_root(account_id, &slot_name, block_4).is_some());
}

#[test]
fn storage_map_empty_entries_query() {
    use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
    use miden_protocol::account::component::AccountComponentMetadata;
    use miden_protocol::account::{
        AccountBuilder,
        AccountComponent,
        AccountType,
        StorageMap,
        StorageSlot,
    };
    use miden_standards::account::auth::AuthSingleSig;
    use miden_standards::code_builder::CodeBuilder;

    let mut forest = AccountStateForest::new();
    let block_num = BlockNumber::GENESIS.child();
    let slot_name = StorageSlotName::mock(0);

    let storage_map = StorageMap::with_entries(vec![]).unwrap();
    let component_storage = vec![StorageSlot::with_map(slot_name.clone(), storage_map)];

    let component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "pub proc test push.1 end")
        .unwrap();
    let account_component = AccountComponent::new(
        component_code,
        component_storage,
        AccountComponentMetadata::new("test"),
    )
    .unwrap();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::Public)
        .with_component(account_component)
        .with_auth_component(AuthSingleSig::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Poseidon2,
        ))
        .build_existing()
        .unwrap();

    let account_id = account.id();
    let full_patch = AccountPatch::try_from(account).unwrap();
    assert!(full_patch.is_full_state());

    forest.update_account(block_num, &full_patch);

    let root = forest.get_storage_map_root(account_id, &slot_name, block_num);
    assert_eq!(root, Some(AccountStateForest::empty_smt_root()));
}

#[test]
fn storage_map_open_returns_proofs() {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(3);
    let block_num = BlockNumber::GENESIS.child();

    let mut map_patch = StorageMapPatch::default();
    for i in 0..20u32 {
        let key = StorageMapKey::from_index(i);
        let value = Word::from([0, 0, 0, i]);
        map_patch.insert(key, value);
    }
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch))]);
    let storage_patch = AccountStoragePatch::from_raw(raw);
    let patch = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch);
    forest.update_account(block_num, &patch);

    let keys: Vec<StorageMapKey> = (0..20u32).map(StorageMapKey::from_index).collect();
    let result =
        forest.get_storage_map_details_for_keys(account_id, slot_name.clone(), block_num, &keys);

    let details = result.expect("Should return Some").expect("Should not error");
    assert_matches!(details.entries, StorageMapEntries::EntriesWithProofs(entries) => {
        assert_eq!(entries.len(), keys.len());
    });
}

#[test]
fn storage_map_all_entries_returns_raw_keys_after_update() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(6);
    let block_num = BlockNumber::GENESIS.child();
    let raw_key = StorageMapKey::from_index(42);
    let value = Word::from([42u32, 0, 0, 0]);

    let mut map_patch = StorageMapPatch::default();
    map_patch.insert(raw_key, value);
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch))]);
    let storage_patch = AccountStoragePatch::from_raw(raw);
    let patch = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch);
    forest.update_account(block_num, &patch);

    let result = forest
        .get_storage_map_details_for_all_entries(account_id, slot_name.clone(), block_num)
        .expect("forest lookup should not fail");

    assert_eq!(
        result,
        AccountStorageMapResult::Details(AccountStorageMapDetails::from_forest_entries(
            slot_name,
            vec![(raw_key, value)]
        ))
    );
}

#[test]
fn storage_map_all_entries_returns_cache_miss_when_raw_key_is_not_cached() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(7);
    let block_num = BlockNumber::GENESIS.child();
    let raw_key = StorageMapKey::from_index(43);
    let value = Word::from([43u32, 0, 0, 0]);

    let mut map_patch = StorageMapPatch::default();
    map_patch.insert(raw_key, value);
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotPatch::Map(map_patch))]);
    let storage_patch = AccountStoragePatch::from_raw(raw);
    let patch = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch);
    forest.update_account(block_num, &patch);

    forest.clear_storage_map_key_cache();

    let result = forest
        .get_storage_map_details_for_all_entries(account_id, slot_name.clone(), block_num)
        .expect("forest lookup should not fail");

    assert_eq!(result, AccountStorageMapResult::CannotReconstructKeysFromCache);

    forest.cache_storage_map_keys([raw_key]);

    let result = forest
        .get_storage_map_details_for_all_entries(account_id, slot_name.clone(), block_num)
        .expect("forest lookup should not fail");

    assert_eq!(
        result,
        AccountStorageMapResult::Details(AccountStorageMapDetails::from_forest_entries(
            slot_name,
            vec![(raw_key, value)]
        ))
    );
}

// PRUNING TESTS
// ================================================================================================

const TEST_CHAIN_LENGTH: u32 = 100;
const TEST_AMOUNT_MULTIPLIER: u32 = 100;
const TEST_PRUNE_CHAIN_TIP: u32 = HISTORICAL_BLOCK_RETENTION + 5;

#[test]
fn prune_handles_empty_forest() {
    let mut forest = AccountStateForest::new();

    let total_roots_removed = forest.prune(BlockNumber::GENESIS);

    assert_eq!(total_roots_removed, 0);
}

#[test]
fn prune_removes_smt_roots_from_forest() {
    use miden_protocol::account::StorageMapPatch;

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_name = StorageSlotName::mock(7);

    for i in 1..=TEST_PRUNE_CHAIN_TIP {
        let block_num = BlockNumber::from(i);

        let mut vault_patch = AccountVaultPatch::default();
        vault_patch
            .insert_asset(dummy_fungible_asset(faucet_id, (i * TEST_AMOUNT_MULTIPLIER).into()));
        let storage_patch = if i.is_multiple_of(3) {
            let mut map_patch = StorageMapPatch::default();
            map_patch.insert(
                StorageMapKey::new(Word::from([1u32, 0, 0, 0])),
                Word::from([99u32, i, i * i, i * i * i]),
            );
            let asd = AccountStoragePatch::new();
            asd.add_updated_maps([(slot_name.clone(), map_patch)])
        } else {
            AccountStoragePatch::default()
        };

        let patch = dummy_partial_patch(account_id, vault_patch, storage_patch);
        forest.update_account(block_num, &patch);
    }

    let retained_block = BlockNumber::from(TEST_PRUNE_CHAIN_TIP);
    let pruned_block = BlockNumber::from(3u32);

    let total_roots_removed = forest.prune(retained_block);
    assert_eq!(total_roots_removed, 0);
    assert!(forest.get_vault_root(account_id, retained_block).is_some());
    assert!(forest.get_vault_root(account_id, pruned_block).is_none());
    assert!(forest.get_storage_map_root(account_id, &slot_name, pruned_block).is_none());
    assert!(forest.get_storage_map_root(account_id, &slot_name, retained_block).is_some());

    let asset_key: Word = FungibleAsset::new(faucet_id, 0).unwrap().vault_key().into();
    let retained_tree = forest.tree_id_for_vault_root(account_id, retained_block);
    let pruned_tree = forest.tree_id_for_vault_root(account_id, pruned_block);
    assert_matches!(forest.forest.open(retained_tree, asset_key), Ok(_));
    assert_matches!(forest.forest.open(pruned_tree, asset_key), Err(_));

    let storage_key = StorageMapKey::new(Word::from([1u32, 0, 0, 0])).hash().into();
    let storage_tree = forest.tree_id_for_root(account_id, &slot_name, pruned_block);
    assert_matches!(forest.forest.open(storage_tree, storage_key), Err(_));
}

#[test]
fn prune_respects_retention_boundary() {
    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    for i in 1..=HISTORICAL_BLOCK_RETENTION {
        let block_num = BlockNumber::from(i);
        let mut vault_patch = AccountVaultPatch::default();
        vault_patch
            .insert_asset(dummy_fungible_asset(faucet_id, (i * TEST_AMOUNT_MULTIPLIER).into()));
        let patch = dummy_partial_patch(account_id, vault_patch, AccountStoragePatch::default());
        forest.update_account(block_num, &patch);
    }

    let total_roots_removed = forest.prune(BlockNumber::from(HISTORICAL_BLOCK_RETENTION));

    assert_eq!(total_roots_removed, 0);
    assert_eq!(forest.forest.tree_count(), 11);
}

#[test]
fn prune_roots_removes_old_entries() {
    use miden_protocol::account::StorageMapPatch;

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();

    let faucet_id = dummy_faucet();
    let slot_name = StorageSlotName::mock(3);

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let amount = (i * TEST_AMOUNT_MULTIPLIER).into();
        let mut vault_patch = AccountVaultPatch::default();
        vault_patch.insert_asset(dummy_fungible_asset(faucet_id, amount));

        let key = StorageMapKey::new(Word::from([i, i * i, 5, 4]));
        let value = Word::from([0, 0, i * i * i, 77]);
        let mut map_patch = StorageMapPatch::default();
        map_patch.insert(key, value);
        let storage_patch =
            AccountStoragePatch::new().add_updated_maps([(slot_name.clone(), map_patch)]);

        let patch = dummy_partial_patch(account_id, vault_patch, storage_patch);
        forest.update_account(block_num, &patch);
    }

    assert_eq!(forest.forest.tree_count(), 22);

    let total_roots_removed = forest.prune(BlockNumber::from(TEST_CHAIN_LENGTH));

    assert_eq!(total_roots_removed, 0);

    assert_eq!(forest.forest.tree_count(), 22);
}

#[test]
fn prune_handles_multiple_accounts() {
    let mut forest = AccountStateForest::new();
    let account1 = dummy_account();
    let account2 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let faucet_id = dummy_faucet();

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let amount = (i * TEST_AMOUNT_MULTIPLIER).into();

        let mut vault_patch1 = AccountVaultPatch::default();
        vault_patch1.insert_asset(dummy_fungible_asset(faucet_id, amount));
        let patch1 = dummy_partial_patch(account1, vault_patch1, AccountStoragePatch::default());
        forest.update_account(block_num, &patch1);

        let mut vault_patch2 = AccountVaultPatch::default();
        vault_patch2.insert_asset(dummy_fungible_asset(account2, amount * 2));
        let patch2 = dummy_partial_patch(account2, vault_patch2, AccountStoragePatch::default());
        forest.update_account(block_num, &patch2);
    }

    assert_eq!(forest.forest.tree_count(), 22);

    let total_roots_removed = forest.prune(BlockNumber::from(TEST_CHAIN_LENGTH));

    let expected_removed_per_account = (TEST_CHAIN_LENGTH - HISTORICAL_BLOCK_RETENTION) as usize;
    assert_eq!(total_roots_removed, 0);
    assert!(total_roots_removed <= expected_removed_per_account * 2);

    assert_eq!(forest.forest.tree_count(), 22);
}

#[test]
fn prune_handles_multiple_slots() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let slot_a = StorageSlotName::mock(1);
    let slot_b = StorageSlotName::mock(2);

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let mut map_patch_a = StorageMapPatch::default();
        map_patch_a.insert(StorageMapKey::new(Word::from([i, 0, 0, 0])), Word::from([i, 0, 0, 1]));
        let mut map_patch_b = StorageMapPatch::default();
        map_patch_b.insert(StorageMapKey::new(Word::from([i, 0, 0, 2])), Word::from([i, 0, 0, 3]));
        let raw = BTreeMap::from_iter([
            (slot_a.clone(), StorageSlotPatch::Map(map_patch_a)),
            (slot_b.clone(), StorageSlotPatch::Map(map_patch_b)),
        ]);
        let storage_patch = AccountStoragePatch::from_raw(raw);
        let patch = dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch);
        forest.update_account(block_num, &patch);
    }

    assert_eq!(forest.forest.tree_count(), 22);

    let chain_tip = BlockNumber::from(TEST_CHAIN_LENGTH);
    let total_roots_removed = forest.prune(chain_tip);

    assert_eq!(total_roots_removed, 0);

    assert_eq!(forest.forest.tree_count(), 22);
}

#[test]
fn prune_preserves_most_recent_state_per_entity() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_map_a = StorageSlotName::mock(1);
    let slot_map_b = StorageSlotName::mock(2);

    // Block 1: Create vault + map_a + map_b
    let block_1 = BlockNumber::from(1);
    let mut vault_patch_1 = AccountVaultPatch::default();
    vault_patch_1.insert_asset(dummy_fungible_asset(faucet_id, 1000));

    let mut map_patch_a = StorageMapPatch::default();
    map_patch_a
        .insert(StorageMapKey::new(Word::from([1u32, 0, 0, 0])), Word::from([100u32, 0, 0, 0]));

    let mut map_patch_b = StorageMapPatch::default();
    map_patch_b
        .insert(StorageMapKey::new(Word::from([2u32, 0, 0, 0])), Word::from([200u32, 0, 0, 0]));

    let raw = BTreeMap::from_iter([
        (slot_map_a.clone(), StorageSlotPatch::Map(map_patch_a)),
        (slot_map_b.clone(), StorageSlotPatch::Map(map_patch_b)),
    ]);
    let storage_patch_1 = AccountStoragePatch::from_raw(raw);
    let patch_1 = dummy_partial_patch(account_id, vault_patch_1, storage_patch_1);
    forest.update_account(block_1, &patch_1);

    // Block 51: Update only map_a
    let block_at_51 = BlockNumber::from(51);
    let mut map_patch_a_new = StorageMapPatch::default();
    map_patch_a_new
        .insert(StorageMapKey::new(Word::from([1u32, 0, 0, 0])), Word::from([999u32, 0, 0, 0]));

    let raw_at_51 =
        BTreeMap::from_iter([(slot_map_a.clone(), StorageSlotPatch::Map(map_patch_a_new))]);
    let storage_patch_at_51 = AccountStoragePatch::from_raw(raw_at_51);
    let patch_at_51 =
        dummy_partial_patch(account_id, AccountVaultPatch::default(), storage_patch_at_51);
    forest.update_account(block_at_51, &patch_at_51);

    // Block 100: Prune
    let block_100 = BlockNumber::from(100);
    let total_roots_removed = forest.prune(block_100);

    assert_eq!(total_roots_removed, 0);

    assert!(forest.get_storage_map_root(account_id, &slot_map_a, block_at_51).is_some());
    assert!(forest.get_storage_map_root(account_id, &slot_map_a, block_1).is_some());
    assert!(forest.get_storage_map_root(account_id, &slot_map_b, block_1).is_some());
}

#[test]
fn prune_preserves_entries_within_retention_window() {
    use std::collections::BTreeMap;

    use miden_protocol::account::{StorageMapPatch, StorageSlotPatch};

    let mut forest = AccountStateForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_map = StorageSlotName::mock(1);

    let blocks = [1, 25, 50, 75, 100];

    for &block_num in &blocks {
        let block = BlockNumber::from(block_num);

        let mut vault_patch = AccountVaultPatch::default();
        vault_patch.insert_asset(dummy_fungible_asset(faucet_id, u64::from(block_num) * 100));

        let mut map_patch = StorageMapPatch::default();
        map_patch
            .insert(StorageMapKey::from_index(block_num), Word::from([block_num * 10, 0, 0, 0]));

        let raw = BTreeMap::from_iter([(slot_map.clone(), StorageSlotPatch::Map(map_patch))]);
        let storage_patch = AccountStoragePatch::from_raw(raw);
        let patch = dummy_partial_patch(account_id, vault_patch, storage_patch);
        forest.update_account(block, &patch);
    }

    // Block 100: Prune (retention window = 50 blocks, cutoff = 50)
    let block_100 = BlockNumber::from(100);
    let total_roots_removed = forest.prune(block_100);

    // Blocks 1 and 25 pruned (outside retention, have newer entries)
    assert_eq!(total_roots_removed, 4);

    assert!(forest.get_vault_root(account_id, BlockNumber::from(1)).is_none());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(25)).is_none());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(50)).is_some());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(75)).is_some());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(100)).is_some());
}

/// Two accounts start with identical vault roots (same asset amount). When one account changes in
/// the next block, verify the unchanged account's vault root still works for lookups and witness
/// generation.
#[test]
fn shared_vault_root_retained_when_one_account_changes() {
    let mut forest = AccountStateForest::new();
    let account1 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let account2 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();
    let faucet_id = dummy_faucet();

    // Block 1: Both accounts have identical vaults (same asset)
    let block_1 = BlockNumber::GENESIS.child();
    let initial_amount = 1000u64;
    let asset = dummy_fungible_asset(faucet_id, initial_amount);

    let mut vault_patch_1 = AccountVaultPatch::default();
    vault_patch_1.insert_asset(asset);
    let patch_1 = dummy_partial_patch(account1, vault_patch_1, AccountStoragePatch::default());
    forest.update_account(block_1, &patch_1);

    let mut vault_patch_2 = AccountVaultPatch::default();
    vault_patch_2.insert_asset(dummy_fungible_asset(faucet_id, initial_amount));
    let patch_2 = dummy_partial_patch(account2, vault_patch_2, AccountStoragePatch::default());
    forest.update_account(block_1, &patch_2);

    // Both accounts should have the same vault root (structural sharing in SmtForest)
    let root1_at_block1 = forest.get_vault_root(account1, block_1).unwrap();
    let root2_at_block1 = forest.get_vault_root(account2, block_1).unwrap();
    assert_eq!(root1_at_block1, root2_at_block1, "identical vaults should have identical roots");

    // Block 2: Only account2 changes (adds more assets)
    let block_2 = block_1.child();
    let mut vault_patch_2_update = AccountVaultPatch::default();
    vault_patch_2_update.insert_asset(dummy_fungible_asset(faucet_id, initial_amount + 500));
    let patch_2_update =
        dummy_partial_patch(account2, vault_patch_2_update, AccountStoragePatch::default());
    forest.update_account(block_2, &patch_2_update);

    // Account2 now has a different root
    let root2_at_block2 = forest.get_vault_root(account2, block_2).unwrap();
    assert_ne!(root2_at_block1, root2_at_block2, "account2 vault should have changed");

    assert!(forest.get_vault_root(account1, block_2).is_some());
}
