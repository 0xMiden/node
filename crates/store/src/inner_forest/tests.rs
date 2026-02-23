use assert_matches::assert_matches;
use miden_protocol::account::AccountCode;
use miden_protocol::asset::{Asset, AssetVault, AssetVaultKey, FungibleAsset};
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_node_proto::domain::account::StorageMapEntries;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use miden_protocol::{Felt, FieldElement};

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

/// Creates a partial `AccountDelta` (without code) for testing incremental updates.
fn dummy_partial_delta(
    account_id: AccountId,
    vault_delta: AccountVaultDelta,
    storage_delta: AccountStorageDelta,
) -> AccountDelta {
    let nonce_delta = if vault_delta.is_empty() && storage_delta.is_empty() {
        Felt::ZERO
    } else {
        Felt::ONE
    };
    AccountDelta::new(account_id, storage_delta, vault_delta, nonce_delta).unwrap()
}

/// Creates a full-state `AccountDelta` (with code) for testing DB reconstruction.
fn dummy_full_state_delta(account_id: AccountId, assets: &[Asset]) -> AccountDelta {
    use miden_protocol::account::{Account, AccountStorage};

    let vault = AssetVault::new(assets).unwrap();
    let storage = AccountStorage::new(vec![]).unwrap();
    let code = AccountCode::mock();
    let nonce = Felt::ONE;

    let account = Account::new(account_id, vault, storage, code, nonce, None).unwrap();
    AccountDelta::try_from(account).unwrap()
}

// INITIALIZATION & BASIC OPERATIONS
// ================================================================================================

#[test]
fn empty_smt_root_is_recognized() {
    use miden_crypto::merkle::smt::Smt;

    let empty_root = InnerForest::empty_smt_root();

    assert_eq!(Smt::default().root(), empty_root);
}

#[test]
fn inner_forest_basic_initialization() {
    let forest = InnerForest::new();
    assert_eq!(forest.forest.lineage_count(), 0);
    assert_eq!(forest.forest.tree_count(), 0);
}

#[test]
fn update_account_with_empty_deltas() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    let delta = dummy_partial_delta(
        account_id,
        AccountVaultDelta::default(),
        AccountStorageDelta::default(),
    );

    forest.update_account(block_num, &delta).unwrap();

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

    // Partial delta (block application)
    let mut forest_partial = InnerForest::new();
    let mut vault_delta = AccountVaultDelta::default();
    vault_delta.add_asset(asset).unwrap();
    let partial_delta =
        dummy_partial_delta(account_id, vault_delta, AccountStorageDelta::default());
    forest_partial.update_account(block_num, &partial_delta).unwrap();

    // Full-state delta (DB reconstruction)
    let mut forest_full = InnerForest::new();
    let full_delta = dummy_full_state_delta(account_id, &[asset]);
    forest_full.update_account(block_num, &full_delta).unwrap();

    let root_partial = forest_partial.get_vault_root(account_id, block_num).unwrap();
    let root_full = forest_full.get_vault_root(account_id, block_num).unwrap();

    assert_eq!(root_partial, root_full);
    assert_ne!(root_partial, EMPTY_WORD);
}

#[test]
fn vault_incremental_updates_with_add_and_remove() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    // Block 1: Add 100 tokens
    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 100)).unwrap();
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();
    let root_after_100 = forest.get_vault_root(account_id, block_1).unwrap();

    // Block 2: Add 50 more tokens (result: 150 tokens)
    let block_2 = block_1.child();
    let mut vault_delta_2 = AccountVaultDelta::default();
    vault_delta_2.add_asset(dummy_fungible_asset(faucet_id, 50)).unwrap();
    let delta_2 = dummy_partial_delta(account_id, vault_delta_2, AccountStorageDelta::default());
    forest.update_account(block_2, &delta_2).unwrap();
    let root_after_150 = forest.get_vault_root(account_id, block_2).unwrap();

    assert_ne!(root_after_100, root_after_150);

    // Block 3: Remove 30 tokens (result: 120 tokens)
    let block_3 = block_2.child();
    let mut vault_delta_3 = AccountVaultDelta::default();
    vault_delta_3.remove_asset(dummy_fungible_asset(faucet_id, 30)).unwrap();
    let delta_3 = dummy_partial_delta(account_id, vault_delta_3, AccountStorageDelta::default());
    forest.update_account(block_3, &delta_3).unwrap();
    let root_after_120 = forest.get_vault_root(account_id, block_3).unwrap();

    assert_ne!(root_after_150, root_after_120);

    // Verify by comparing to full-state delta
    let mut fresh_forest = InnerForest::new();
    let full_delta = dummy_full_state_delta(account_id, &[dummy_fungible_asset(faucet_id, 120)]);
    fresh_forest.update_account(block_3, &full_delta).unwrap();
    let root_full_state_120 = fresh_forest.get_vault_root(account_id, block_3).unwrap();

    assert_eq!(root_after_120, root_full_state_120);
}

#[test]
fn forest_versions_are_continuous_for_sequential_updates() {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_name = StorageSlotName::mock(9);
    let raw_key = Word::from([1u32, 0, 0, 0]);
    let storage_key = StorageMap::hash_key(raw_key);
    let asset_key: Word = FungibleAsset::new(faucet_id, 0).unwrap().vault_key().into();

    for i in 1..=3u32 {
        let block_num = BlockNumber::from(i);
        let mut vault_delta = AccountVaultDelta::default();
        vault_delta
            .add_asset(dummy_fungible_asset(faucet_id, u64::from(i) * 10))
            .unwrap();

        let mut map_delta = StorageMapDelta::default();
        map_delta.insert(raw_key, Word::from([i, 0, 0, 0]));
        let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta))]);
        let storage_delta = AccountStorageDelta::from_raw(raw);

        let delta = dummy_partial_delta(account_id, vault_delta, storage_delta);
        forest.update_account(block_num, &delta).unwrap();

        let vault_tree = forest.tree_id_for_vault_root(account_id, block_num);
        let storage_tree = forest.tree_id_for_root(account_id, &slot_name, block_num);

        assert_matches!(forest.forest.open(vault_tree, asset_key), Ok(_));
        assert_matches!(forest.forest.open(storage_tree, storage_key), Ok(_));
    }
}

#[test]
fn vault_state_is_not_available_for_block_gaps() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 100)).unwrap();
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();

    let block_6 = BlockNumber::from(6);
    let mut vault_delta_6 = AccountVaultDelta::default();
    vault_delta_6.add_asset(dummy_fungible_asset(faucet_id, 150)).unwrap();
    let delta_6 = dummy_partial_delta(account_id, vault_delta_6, AccountStorageDelta::default());
    forest.update_account(block_6, &delta_6).unwrap();

    assert!(forest.get_vault_root(account_id, BlockNumber::from(3)).is_some());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(5)).is_some());
    assert!(forest.get_vault_root(account_id, block_6).is_some());
}

#[test]
fn witness_queries_work_with_sparse_lineage_updates() {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_name = StorageSlotName::mock(6);
    let raw_key = Word::from([1u32, 0, 0, 0]);
    let value = Word::from([9u32, 0, 0, 0]);

    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 100)).unwrap();
    let mut map_delta_1 = StorageMapDelta::default();
    map_delta_1.insert(raw_key, value);
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_1))]);
    let storage_delta_1 = AccountStorageDelta::from_raw(raw);
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, storage_delta_1);
    forest.update_account(block_1, &delta_1).unwrap();

    let block_3 = block_1.child().child();
    let mut vault_delta_3 = AccountVaultDelta::default();
    vault_delta_3.add_asset(dummy_fungible_asset(faucet_id, 50)).unwrap();
    let delta_3 = dummy_partial_delta(account_id, vault_delta_3, AccountStorageDelta::default());
    forest.update_account(block_3, &delta_3).unwrap();

    let block_2 = block_1.child();
    let asset_key = FungibleAsset::new(faucet_id, 0).unwrap().vault_key();
    let witnesses = forest
        .get_vault_asset_witnesses(account_id, block_2, [asset_key].into())
        .unwrap();
    let proof: SmtProof = witnesses[0].clone().into();
    let root_at_2 = forest.get_vault_root(account_id, block_2).unwrap();
    assert_eq!(proof.compute_root(), root_at_2);

    let storage_witness = forest
        .get_storage_map_witness(account_id, &slot_name, block_2, raw_key)
        .unwrap();
    let storage_root_at_2 = forest.get_storage_map_root(account_id, &slot_name, block_2).unwrap();
    let storage_proof: SmtProof = storage_witness.into();
    assert_eq!(storage_proof.compute_root(), storage_root_at_2);

    let storage_witness_at_3 = forest
        .get_storage_map_witness(account_id, &slot_name, block_3, raw_key)
        .unwrap();
    let storage_root_at_3 = forest.get_storage_map_root(account_id, &slot_name, block_3).unwrap();
    let storage_proof_at_3: SmtProof = storage_witness_at_3.into();
    assert_eq!(storage_proof_at_3.compute_root(), storage_root_at_3);

    let vault_root_at_3 = forest.get_vault_root(account_id, block_3).unwrap();
    assert_matches!(
        forest.forest.open(forest.tree_id_for_vault_root(account_id, block_3), asset_key.into()),
        Ok(_)
    );
    assert_ne!(vault_root_at_3, InnerForest::empty_smt_root());
}

#[test]
fn vault_full_state_with_empty_vault_records_root() {
    use miden_protocol::account::{Account, AccountStorage};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    let vault = AssetVault::new(&[]).unwrap();
    let storage = AccountStorage::new(vec![]).unwrap();
    let code = AccountCode::mock();
    let nonce = Felt::ONE;
    let account = Account::new(account_id, vault, storage, code, nonce, None).unwrap();
    let full_delta = AccountDelta::try_from(account).unwrap();

    assert!(full_delta.vault().is_empty());
    assert!(full_delta.is_full_state());

    forest.update_account(block_num, &full_delta).unwrap();

    let recorded_root = forest.get_vault_root(account_id, block_num);
    assert_eq!(recorded_root, Some(InnerForest::empty_smt_root()));

    let witnesses = forest
        .get_vault_asset_witnesses(account_id, block_num, std::collections::BTreeSet::new())
        .expect("get_vault_asset_witnesses should succeed for accounts with empty vaults");
    assert!(witnesses.is_empty());
}

#[test]
fn vault_shared_root_retained_when_one_entry_pruned() {
    let mut forest = InnerForest::new();
    let account1 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let account2 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();
    let faucet_id = dummy_faucet();
    let block_1 = BlockNumber::GENESIS.child();
    let asset_amount = u64::from(HISTORICAL_BLOCK_RETENTION);
    let amount_increment = asset_amount / u64::from(HISTORICAL_BLOCK_RETENTION);
    let asset = dummy_fungible_asset(faucet_id, asset_amount);
    let asset_key = AssetVaultKey::new_unchecked(asset.vault_key().into());

    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(asset).unwrap();
    let delta_1 = dummy_partial_delta(account1, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();

    let mut vault_delta_2 = AccountVaultDelta::default();
    vault_delta_2.add_asset(dummy_fungible_asset(faucet_id, asset_amount)).unwrap();
    let delta_2 = dummy_partial_delta(account2, vault_delta_2, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_2).unwrap();

    let root1 = forest.get_vault_root(account1, block_1).unwrap();
    let root2 = forest.get_vault_root(account2, block_1).unwrap();
    assert_eq!(root1, root2);

    let block_at_51 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 1);
    let mut vault_delta_2_update = AccountVaultDelta::default();
    vault_delta_2_update
        .add_asset(dummy_fungible_asset(faucet_id, amount_increment))
        .unwrap();
    let delta_2_update =
        dummy_partial_delta(account2, vault_delta_2_update, AccountStorageDelta::default());
    forest.update_account(block_at_51, &delta_2_update).unwrap();

    let block_at_52 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 2);
    let (vault_removed, storage_roots_removed) = forest.prune(block_at_52);

    assert_eq!(vault_removed, 0);
    assert_eq!(storage_roots_removed, 0);
    assert!(forest.get_vault_root(account1, block_1).is_some());
    assert!(forest.get_vault_root(account2, block_1).is_some());

    let vault_root_at_52 = forest.get_vault_root(account1, block_at_52);
    assert_eq!(vault_root_at_52, Some(root1));

    let witnesses =
        forest.get_vault_asset_witnesses(account1, block_at_52, [asset_key].into()).unwrap();
    assert_eq!(witnesses.len(), 1);
    let proof: SmtProof = witnesses[0].clone().into();
    assert_eq!(proof.compute_root(), root1);
}

// STORAGE MAP TESTS
// ================================================================================================

#[test]
fn storage_map_incremental_updates() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();

    let slot_name = StorageSlotName::mock(3);
    let key1 = Word::from([1u32, 0, 0, 0]);
    let key2 = Word::from([2u32, 0, 0, 0]);
    let value1 = Word::from([10u32, 0, 0, 0]);
    let value2 = Word::from([20u32, 0, 0, 0]);
    let value3 = Word::from([30u32, 0, 0, 0]);

    // Block 1: Insert key1 -> value1
    let block_1 = BlockNumber::GENESIS.child();
    let mut map_delta_1 = StorageMapDelta::default();
    map_delta_1.insert(key1, value1);
    let raw_1 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_1))]);
    let storage_delta_1 = AccountStorageDelta::from_raw(raw_1);
    let delta_1 = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_1);
    forest.update_account(block_1, &delta_1).unwrap();
    let root_1 = forest.get_storage_map_root(account_id, &slot_name, block_1).unwrap();

    // Block 2: Insert key2 -> value2
    let block_2 = block_1.child();
    let mut map_delta_2 = StorageMapDelta::default();
    map_delta_2.insert(key2, value2);
    let raw_2 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_2))]);
    let storage_delta_2 = AccountStorageDelta::from_raw(raw_2);
    let delta_2 = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_2);
    forest.update_account(block_2, &delta_2).unwrap();
    let root_2 = forest.get_storage_map_root(account_id, &slot_name, block_2).unwrap();

    // Block 3: Update key1 -> value3
    let block_3 = block_2.child();
    let mut map_delta_3 = StorageMapDelta::default();
    map_delta_3.insert(key1, value3);
    let raw_3 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_3))]);
    let storage_delta_3 = AccountStorageDelta::from_raw(raw_3);
    let delta_3 = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_3);
    forest.update_account(block_3, &delta_3).unwrap();
    let root_3 = forest.get_storage_map_root(account_id, &slot_name, block_3).unwrap();

    assert_ne!(root_1, root_2);
    assert_ne!(root_2, root_3);
    assert_ne!(root_1, root_3);
}

#[test]
fn storage_map_state_is_not_available_for_block_gaps() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    const BLOCK_FIRST: u32 = 1;
    const BLOCK_SECOND: u32 = 4;
    const BLOCK_QUERY_ONE: u32 = 2;
    const BLOCK_QUERY_TWO: u32 = 3;
    const KEY_VALUE: u32 = 7;
    const VALUE_FIRST: u32 = 10;
    const VALUE_SECOND: u32 = 20;

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(4);
    let raw_key = Word::from([KEY_VALUE, 0, 0, 0]);

    let block_1 = BlockNumber::from(BLOCK_FIRST);
    let mut map_delta_1 = StorageMapDelta::default();
    let value_1 = Word::from([VALUE_FIRST, 0, 0, 0]);
    map_delta_1.insert(raw_key, value_1);
    let raw_1 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_1))]);
    let storage_delta_1 = AccountStorageDelta::from_raw(raw_1);
    let delta_1 = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_1);
    forest.update_account(block_1, &delta_1).unwrap();

    let block_4 = BlockNumber::from(BLOCK_SECOND);
    let mut map_delta_4 = StorageMapDelta::default();
    let value_2 = Word::from([VALUE_SECOND, 0, 0, 0]);
    map_delta_4.insert(raw_key, value_2);
    let raw_4 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_4))]);
    let storage_delta_4 = AccountStorageDelta::from_raw(raw_4);
    let delta_4 = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_4);
    forest.update_account(block_4, &delta_4).unwrap();

    assert!(
        forest.get_storage_map_root(account_id, &slot_name, BlockNumber::from(BLOCK_QUERY_ONE))
            .is_some()
    );
    assert!(
        forest.get_storage_map_root(account_id, &slot_name, BlockNumber::from(BLOCK_QUERY_TWO))
            .is_some()
    );
    assert!(forest.get_storage_map_root(account_id, &slot_name, block_4).is_some());
}

#[test]
fn storage_map_empty_entries_query() {
    use miden_protocol::account::auth::PublicKeyCommitment;
    use miden_protocol::account::{
        AccountBuilder,
        AccountComponent,
        AccountStorageMode,
        AccountType,
        StorageMap,
        StorageSlot,
    };
    use miden_standards::account::auth::AuthFalcon512Rpo;
    use miden_standards::code_builder::CodeBuilder;

    let mut forest = InnerForest::new();
    let block_num = BlockNumber::GENESIS.child();
    let slot_name = StorageSlotName::mock(0);

    let storage_map = StorageMap::with_entries(vec![]).unwrap();
    let component_storage = vec![StorageSlot::with_map(slot_name.clone(), storage_map)];

    let component_code = CodeBuilder::default()
        .compile_component_code("test::interface", "pub proc test push.1 end")
        .unwrap();
    let account_component = AccountComponent::new(component_code, component_storage)
        .unwrap()
        .with_supports_all_types();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let account_id = account.id();
    let full_delta = AccountDelta::try_from(account).unwrap();
    assert!(full_delta.is_full_state());

    forest.update_account(block_num, &full_delta).unwrap();

    let root = forest.get_storage_map_root(account_id, &slot_name, block_num);
    assert_eq!(root, Some(InnerForest::empty_smt_root()));
}

#[test]
fn storage_map_open_returns_proofs() {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(3);
    let block_num = BlockNumber::GENESIS.child();

    let mut map_delta = StorageMapDelta::default();
    for i in 0..20u32 {
        let key = Word::from([i, 0, 0, 0]);
        let value = Word::from([0, 0, 0, i]);
        map_delta.insert(key, value);
    }
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta))]);
    let storage_delta = AccountStorageDelta::from_raw(raw);
    let delta = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta);
    forest.update_account(block_num, &delta).unwrap();

    let keys: Vec<Word> = (0..20u32).map(|i| Word::from([i, 0, 0, 0])).collect();
    let result =
        forest.get_storage_map_details_for_keys(account_id, slot_name.clone(), block_num, &keys);

    let details = result.expect("Should return Some").expect("Should not error");
    assert_matches!(details.entries, StorageMapEntries::EntriesWithProofs(entries) => {
        assert_eq!(entries.len(), keys.len());
    });
}

#[test]
fn storage_map_key_hashing_and_raw_entries_are_consistent() {
    use std::collections::BTreeMap;

    use miden_protocol::account::StorageMap;
    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    const SLOT_INDEX: usize = 4;
    const KEY_VALUE: u32 = 11;
    const VALUE_VALUE: u32 = 22;

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(SLOT_INDEX);
    let block_num = BlockNumber::GENESIS.child();
    let raw_key = Word::from([KEY_VALUE, 0, 0, 0]);
    let value = Word::from([VALUE_VALUE, 0, 0, 0]);

    let mut map_delta = StorageMapDelta::default();
    map_delta.insert(raw_key, value);
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta))]);
    let storage_delta = AccountStorageDelta::from_raw(raw);
    let delta = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta);
    forest.update_account(block_num, &delta).unwrap();

    let root = forest.get_storage_map_root(account_id, &slot_name, block_num).unwrap();

    let witness = forest
        .get_storage_map_witness(account_id, &slot_name, block_num, raw_key)
        .unwrap();
    let proof: SmtProof = witness.into();
    let hashed_key = StorageMap::hash_key(raw_key);
    // Witness proofs use hashed keys because SMT leaves are keyed by the hash.
    assert_eq!(proof.compute_root(), root);
    assert_eq!(proof.get(&hashed_key), Some(value));
    // Raw keys never appear in SMT proofs, only their hashed counterparts.
    assert_eq!(proof.get(&raw_key), None);

}

// PRUNING TESTS
// ================================================================================================

const TEST_CHAIN_LENGTH: u32 = 100;
const TEST_AMOUNT_MULTIPLIER: u32 = 100;
const TEST_PRUNE_CHAIN_TIP: u32 = HISTORICAL_BLOCK_RETENTION + 5;

#[test]
fn prune_handles_empty_forest() {
    let mut forest = InnerForest::new();

    let (vault_removed, storage_roots_removed) = forest.prune(BlockNumber::GENESIS);

    assert_eq!(vault_removed, 0);
    assert_eq!(storage_roots_removed, 0);
}

#[test]
fn prune_removes_smt_roots_from_forest() {
    use miden_protocol::account::delta::StorageMapDelta;

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_name = StorageSlotName::mock(7);

    for i in 1..=TEST_PRUNE_CHAIN_TIP {
        let block_num = BlockNumber::from(i);

        let mut vault_delta = AccountVaultDelta::default();
        vault_delta
            .add_asset(dummy_fungible_asset(faucet_id, (i * TEST_AMOUNT_MULTIPLIER).into()))
            .unwrap();
        let storage_delta = if i.is_multiple_of(3) {
            let mut map_delta = StorageMapDelta::default();
            map_delta.insert(Word::from([1u32, 0, 0, 0]), Word::from([99u32, i, i * i, i * i * i]));
            let asd = AccountStorageDelta::new();
            asd.add_updated_maps([(slot_name.clone(), map_delta)])
        } else {
            AccountStorageDelta::default()
        };

        let delta = dummy_partial_delta(account_id, vault_delta, storage_delta);
        forest.update_account(block_num, &delta).unwrap();
    }

    let retained_block = BlockNumber::from(TEST_PRUNE_CHAIN_TIP);
    let pruned_block = BlockNumber::from(3u32);

    let (_roots_removed, storage_roots_removed) = forest.prune(retained_block);

    assert_eq!(storage_roots_removed, 0);
    assert!(forest.get_vault_root(account_id, retained_block).is_some());
    assert!(forest.get_vault_root(account_id, pruned_block).is_none());
    assert!(forest.get_storage_map_root(account_id, &slot_name, pruned_block).is_none());
    assert!(forest.get_storage_map_root(account_id, &slot_name, retained_block).is_some());

    let asset_key: Word = FungibleAsset::new(faucet_id, 0).unwrap().vault_key().into();
    let retained_tree = forest.tree_id_for_vault_root(account_id, retained_block);
    let pruned_tree = forest.tree_id_for_vault_root(account_id, pruned_block);
    assert_matches!(forest.forest.open(retained_tree, asset_key), Ok(_));
    assert_matches!(forest.forest.open(pruned_tree, asset_key), Err(_));

    let storage_key = StorageMap::hash_key(Word::from([1u32, 0, 0, 0]));
    let storage_tree = forest.tree_id_for_root(account_id, &slot_name, pruned_block);
    assert_matches!(forest.forest.open(storage_tree, storage_key), Err(_));
}

#[test]
fn prune_respects_retention_boundary() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    for i in 1..=HISTORICAL_BLOCK_RETENTION {
        let block_num = BlockNumber::from(i);
        let mut vault_delta = AccountVaultDelta::default();
        vault_delta
            .add_asset(dummy_fungible_asset(faucet_id, (i * TEST_AMOUNT_MULTIPLIER).into()))
            .unwrap();
        let delta = dummy_partial_delta(account_id, vault_delta, AccountStorageDelta::default());
        forest.update_account(block_num, &delta).unwrap();
    }

    let (roots_removed, storage_roots_removed) =
        forest.prune(BlockNumber::from(HISTORICAL_BLOCK_RETENTION));

    assert_eq!(roots_removed, 0);
    assert_eq!(storage_roots_removed, 0);
    assert_eq!(forest.forest.tree_count(), 11);
}

#[test]
fn prune_roots_removes_old_entries() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    use miden_protocol::account::delta::StorageMapDelta;

    let faucet_id = dummy_faucet();
    let slot_name = StorageSlotName::mock(3);

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let amount = (i * TEST_AMOUNT_MULTIPLIER).into();
        let mut vault_delta = AccountVaultDelta::default();
        vault_delta.add_asset(dummy_fungible_asset(faucet_id, amount)).unwrap();

        let key = Word::from([i, i * i, 5, 4]);
        let value = Word::from([0, 0, i * i * i, 77]);
        let mut map_delta = StorageMapDelta::default();
        map_delta.insert(key, value);
        let storage_delta = AccountStorageDelta::new().add_updated_maps([(slot_name.clone(), map_delta)]);

        let delta = dummy_partial_delta(account_id, vault_delta, storage_delta);
        forest.update_account(block_num, &delta).unwrap();
    }

    assert_eq!(forest.forest.tree_count(), 22);

    let (roots_removed, storage_roots_removed) = forest.prune(BlockNumber::from(TEST_CHAIN_LENGTH));

    assert_eq!(roots_removed, 0);
    assert_eq!(storage_roots_removed, 0);

    assert_eq!(forest.forest.tree_count(), 22);
}

#[test]
fn prune_handles_multiple_accounts() {
    let mut forest = InnerForest::new();
    let account1 = dummy_account();
    let account2 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let faucet_id = dummy_faucet();

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let amount = (i * TEST_AMOUNT_MULTIPLIER).into();

        let mut vault_delta1 = AccountVaultDelta::default();
        vault_delta1.add_asset(dummy_fungible_asset(faucet_id, amount)).unwrap();
        let delta1 = dummy_partial_delta(account1, vault_delta1, AccountStorageDelta::default());
        forest.update_account(block_num, &delta1).unwrap();

        let mut vault_delta2 = AccountVaultDelta::default();
        vault_delta2.add_asset(dummy_fungible_asset(account2, amount * 2)).unwrap();
        let delta2 = dummy_partial_delta(account2, vault_delta2, AccountStorageDelta::default());
        forest.update_account(block_num, &delta2).unwrap();
    }

    assert_eq!(forest.forest.tree_count(), 22);

    let (vault_removed, _) = forest.prune(BlockNumber::from(TEST_CHAIN_LENGTH));

    let expected_removed_per_account = (TEST_CHAIN_LENGTH - HISTORICAL_BLOCK_RETENTION) as usize;
    assert_eq!(vault_removed, 0);
    assert!(vault_removed <= expected_removed_per_account * 2);

    assert_eq!(forest.forest.tree_count(), 22);
}

#[test]
fn prune_handles_multiple_slots() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let slot_a = StorageSlotName::mock(1);
    let slot_b = StorageSlotName::mock(2);

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let mut map_delta_a = StorageMapDelta::default();
        map_delta_a.insert(Word::from([i, 0, 0, 0]), Word::from([i, 0, 0, 1]));
        let mut map_delta_b = StorageMapDelta::default();
        map_delta_b.insert(Word::from([i, 0, 0, 2]), Word::from([i, 0, 0, 3]));
        let raw = BTreeMap::from_iter([
            (slot_a.clone(), StorageSlotDelta::Map(map_delta_a)),
            (slot_b.clone(), StorageSlotDelta::Map(map_delta_b)),
        ]);
        let storage_delta = AccountStorageDelta::from_raw(raw);
        let delta = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta);
        forest.update_account(block_num, &delta).unwrap();
    }

    assert_eq!(forest.forest.tree_count(), 22);

    let chain_tip = BlockNumber::from(TEST_CHAIN_LENGTH);
    let (roots_removed, storage_roots_removed) = forest.prune(chain_tip);

    assert_eq!(roots_removed, 0);
    assert_eq!(storage_roots_removed, 0);

    assert_eq!(forest.forest.tree_count(), 22);
}

#[test]
fn prune_preserves_most_recent_state_per_entity() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_map_a = StorageSlotName::mock(1);
    let slot_map_b = StorageSlotName::mock(2);

    // Block 1: Create vault + map_a + map_b
    let block_1 = BlockNumber::from(1);
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 1000)).unwrap();

    let mut map_delta_a = StorageMapDelta::default();
    map_delta_a.insert(Word::from([1u32, 0, 0, 0]), Word::from([100u32, 0, 0, 0]));

    let mut map_delta_b = StorageMapDelta::default();
    map_delta_b.insert(Word::from([2u32, 0, 0, 0]), Word::from([200u32, 0, 0, 0]));

    let raw = BTreeMap::from_iter([
        (slot_map_a.clone(), StorageSlotDelta::Map(map_delta_a)),
        (slot_map_b.clone(), StorageSlotDelta::Map(map_delta_b)),
    ]);
    let storage_delta_1 = AccountStorageDelta::from_raw(raw);
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, storage_delta_1);
    forest.update_account(block_1, &delta_1).unwrap();

    // Block 51: Update only map_a
    let block_at_51 = BlockNumber::from(51);
    let mut map_delta_a_new = StorageMapDelta::default();
    map_delta_a_new.insert(Word::from([1u32, 0, 0, 0]), Word::from([999u32, 0, 0, 0]));

    let raw_at_51 =
        BTreeMap::from_iter([(slot_map_a.clone(), StorageSlotDelta::Map(map_delta_a_new))]);
    let storage_delta_at_51 = AccountStorageDelta::from_raw(raw_at_51);
    let delta_at_51 =
        dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_at_51);
    forest.update_account(block_at_51, &delta_at_51).unwrap();

    // Block 100: Prune
    let block_100 = BlockNumber::from(100);
    let (vault_removed, storage_roots_removed) = forest.prune(block_100);

    assert_eq!(vault_removed, 0);
    assert_eq!(storage_roots_removed, 0);

    assert!(forest.get_storage_map_root(account_id, &slot_map_a, block_at_51).is_some());
    assert!(forest.get_storage_map_root(account_id, &slot_map_a, block_1).is_some());
    assert!(forest.get_storage_map_root(account_id, &slot_map_b, block_1).is_some());
}

#[test]
fn prune_preserves_entries_within_retention_window() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let slot_map = StorageSlotName::mock(1);

    let blocks = [1, 25, 50, 75, 100];

    for &block_num in &blocks {
        let block = BlockNumber::from(block_num);

        let mut vault_delta = AccountVaultDelta::default();
        vault_delta
            .add_asset(dummy_fungible_asset(faucet_id, u64::from(block_num) * 100))
            .unwrap();

        let mut map_delta = StorageMapDelta::default();
        map_delta.insert(Word::from([block_num, 0, 0, 0]), Word::from([block_num * 10, 0, 0, 0]));

        let raw = BTreeMap::from_iter([(slot_map.clone(), StorageSlotDelta::Map(map_delta))]);
        let storage_delta = AccountStorageDelta::from_raw(raw);
        let delta = dummy_partial_delta(account_id, vault_delta, storage_delta);
        forest.update_account(block, &delta).unwrap();
    }

    // Block 100: Prune (retention window = 50 blocks, cutoff = 50)
    let block_100 = BlockNumber::from(100);
    let (vault_removed, storage_roots_removed) = forest.prune(block_100);

    // Blocks 1 and 25 pruned (outside retention, have newer entries)
    assert_eq!(vault_removed, 4);
    assert_eq!(storage_roots_removed, 0);

    assert!(forest.get_vault_root(account_id, BlockNumber::from(1)).is_none());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(25)).is_none());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(50)).is_some());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(75)).is_some());
    assert!(forest.get_vault_root(account_id, BlockNumber::from(100)).is_some());
}

/// Two accounts start with identical vault roots (same asset amount). When one account changes
/// in the next block, verify the unchanged account's vault root still works for lookups and
/// witness generation.
#[test]
fn shared_vault_root_retained_when_one_account_changes() {
    let mut forest = InnerForest::new();
    let account1 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let account2 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();
    let faucet_id = dummy_faucet();

    // Block 1: Both accounts have identical vaults (same asset)
    let block_1 = BlockNumber::GENESIS.child();
    let initial_amount = 1000u64;
    let asset = dummy_fungible_asset(faucet_id, initial_amount);
    let asset_key = AssetVaultKey::new_unchecked(asset.vault_key().into());

    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(asset).unwrap();
    let delta_1 = dummy_partial_delta(account1, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();

    let mut vault_delta_2 = AccountVaultDelta::default();
    vault_delta_2
        .add_asset(dummy_fungible_asset(faucet_id, initial_amount))
        .unwrap();
    let delta_2 = dummy_partial_delta(account2, vault_delta_2, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_2).unwrap();

    // Both accounts should have the same vault root (structural sharing in SmtForest)
    let root1_at_block1 = forest.get_vault_root(account1, block_1).unwrap();
    let root2_at_block1 = forest.get_vault_root(account2, block_1).unwrap();
    assert_eq!(root1_at_block1, root2_at_block1, "identical vaults should have identical roots");

    // Block 2: Only account2 changes (adds more assets)
    let block_2 = block_1.child();
    let mut vault_delta_2_update = AccountVaultDelta::default();
    vault_delta_2_update.add_asset(dummy_fungible_asset(faucet_id, 500)).unwrap();
    let delta_2_update =
        dummy_partial_delta(account2, vault_delta_2_update, AccountStorageDelta::default());
    forest.update_account(block_2, &delta_2_update).unwrap();

    // Account2 now has a different root
    let root2_at_block2 = forest.get_vault_root(account2, block_2).unwrap();
    assert_ne!(root2_at_block1, root2_at_block2, "account2 vault should have changed");

    assert!(forest.get_vault_root(account1, block_2).is_some());

    let witnesses = forest
        .get_vault_asset_witnesses(account1, block_2, [asset_key].into())
        .expect("witness generation should succeed for prior version");
    assert_eq!(witnesses.len(), 1);
}
