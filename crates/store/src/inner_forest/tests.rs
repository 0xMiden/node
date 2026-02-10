use assert_matches::assert_matches;
use miden_protocol::account::AccountCode;
use miden_protocol::asset::{Asset, AssetVault, AssetVaultKey, FungibleAsset};
use miden_protocol::crypto::merkle::smt::SmtProof;
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
    use miden_protocol::crypto::merkle::smt::Smt;

    let empty_root = InnerForest::empty_smt_root();

    assert_eq!(Smt::default().root(), empty_root);

    let mut forest = SmtForest::new();
    let entries = vec![(Word::from([1u32, 2, 3, 4]), Word::from([5u32, 6, 7, 8]))];

    assert_matches!(forest.batch_insert(empty_root, entries), Ok(_));
}

#[test]
fn inner_forest_basic_initialization() {
    let forest = InnerForest::new();
    assert!(forest.storage_map_roots.is_empty());
    assert!(forest.vault_roots.is_empty());
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

    assert!(!forest.vault_roots.contains_key(&(account_id, block_num)));
    assert!(forest.storage_map_roots.is_empty());
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

    let root_partial = forest_partial.vault_roots.get(&(account_id, block_num)).unwrap();
    let root_full = forest_full.vault_roots.get(&(account_id, block_num)).unwrap();

    assert_eq!(root_partial, root_full);
    assert_ne!(*root_partial, EMPTY_WORD);
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
    let root_after_100 = forest.vault_roots[&(account_id, block_1)];

    // Block 2: Add 50 more tokens (result: 150 tokens)
    let block_2 = block_1.child();
    let mut vault_delta_2 = AccountVaultDelta::default();
    vault_delta_2.add_asset(dummy_fungible_asset(faucet_id, 50)).unwrap();
    let delta_2 = dummy_partial_delta(account_id, vault_delta_2, AccountStorageDelta::default());
    forest.update_account(block_2, &delta_2).unwrap();
    let root_after_150 = forest.vault_roots[&(account_id, block_2)];

    assert_ne!(root_after_100, root_after_150);

    // Block 3: Remove 30 tokens (result: 120 tokens)
    let block_3 = block_2.child();
    let mut vault_delta_3 = AccountVaultDelta::default();
    vault_delta_3.remove_asset(dummy_fungible_asset(faucet_id, 30)).unwrap();
    let delta_3 = dummy_partial_delta(account_id, vault_delta_3, AccountStorageDelta::default());
    forest.update_account(block_3, &delta_3).unwrap();
    let root_after_120 = forest.vault_roots[&(account_id, block_3)];

    assert_ne!(root_after_150, root_after_120);

    // Verify by comparing to full-state delta
    let mut fresh_forest = InnerForest::new();
    let full_delta = dummy_full_state_delta(account_id, &[dummy_fungible_asset(faucet_id, 120)]);
    fresh_forest.update_account(block_3, &full_delta).unwrap();
    let root_full_state_120 = fresh_forest.vault_roots[&(account_id, block_3)];

    assert_eq!(root_after_120, root_full_state_120);
}

#[test]
fn vault_state_persists_across_block_gaps() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    let get_vault_root = |forest: &InnerForest, account_id: AccountId, block_num: BlockNumber| {
        forest
            .vault_roots
            .range((account_id, BlockNumber::GENESIS)..=(account_id, block_num))
            .next_back()
            .map(|(_, root)| *root)
    };

    // Block 1: Add 100 tokens
    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 100)).unwrap();
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();
    let root_after_block_1 = forest.vault_roots[&(account_id, block_1)];

    // Blocks 2-5: No changes (simulated by not calling update_account)

    // Block 6: Add 50 more tokens (total: 150)
    let block_6 = BlockNumber::from(6);
    let mut vault_delta_6 = AccountVaultDelta::default();
    vault_delta_6.add_asset(dummy_fungible_asset(faucet_id, 150)).unwrap();
    let delta_6 = dummy_partial_delta(account_id, vault_delta_6, AccountStorageDelta::default());
    forest.update_account(block_6, &delta_6).unwrap();
    let root_after_block_6 = forest.vault_roots[&(account_id, block_6)];

    assert_ne!(root_after_block_1, root_after_block_6);

    // Verify range query finds correct previous roots
    assert_eq!(
        get_vault_root(&forest, account_id, BlockNumber::from(3)),
        Some(root_after_block_1)
    );
    assert_eq!(
        get_vault_root(&forest, account_id, BlockNumber::from(5)),
        Some(root_after_block_1)
    );
    assert_eq!(get_vault_root(&forest, account_id, block_6), Some(root_after_block_6));
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

    assert!(
        forest.vault_roots.contains_key(&(account_id, block_num)),
        "vault root should be recorded for full-state deltas with empty vaults"
    );

    let recorded_root = forest.vault_roots[&(account_id, block_num)];
    assert_eq!(recorded_root, InnerForest::empty_smt_root());

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

    let root1 = forest.vault_roots[&(account1, block_1)];
    let root2 = forest.vault_roots[&(account2, block_1)];
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
    let (vault_roots_removed, storage_roots_removed, storage_entries_removed) =
        forest.prune(block_at_52);

    assert_eq!(vault_roots_removed, 1);
    assert_eq!(storage_roots_removed, 0);
    assert_eq!(storage_entries_removed, 0);
    assert!(forest.vault_roots.contains_key(&(account1, block_1)));
    assert!(!forest.vault_roots.contains_key(&(account2, block_1)));
    assert_eq!(forest.vault_roots_by_block[&block_1], vec![account1]);

    let vault_root_at_52 = forest.get_vault_root(account1, block_at_52);
    assert_eq!(vault_root_at_52, Some(root1));

    let witnesses = forest
        .get_vault_asset_witnesses(account1, block_at_52, [asset_key].into())
        .expect("Should be able to get vault witness after pruning");
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
    let root_1 = forest.storage_map_roots[&(account_id, slot_name.clone(), block_1)];

    // Block 2: Insert key2 -> value2
    let block_2 = block_1.child();
    let mut map_delta_2 = StorageMapDelta::default();
    map_delta_2.insert(key2, value2);
    let raw_2 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_2))]);
    let storage_delta_2 = AccountStorageDelta::from_raw(raw_2);
    let delta_2 = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_2);
    forest.update_account(block_2, &delta_2).unwrap();
    let root_2 = forest.storage_map_roots[&(account_id, slot_name.clone(), block_2)];

    // Block 3: Update key1 -> value3
    let block_3 = block_2.child();
    let mut map_delta_3 = StorageMapDelta::default();
    map_delta_3.insert(key1, value3);
    let raw_3 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_3))]);
    let storage_delta_3 = AccountStorageDelta::from_raw(raw_3);
    let delta_3 = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta_3);
    forest.update_account(block_3, &delta_3).unwrap();
    let root_3 = forest.storage_map_roots[&(account_id, slot_name, block_3)];

    assert_ne!(root_1, root_2);
    assert_ne!(root_2, root_3);
    assert_ne!(root_1, root_3);
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

    assert!(
        forest
            .storage_map_roots
            .contains_key(&(account_id, slot_name.clone(), block_num)),
        "storage_map_roots should have an entry for the empty map"
    );

    let result = forest.storage_map_entries(account_id, slot_name.clone(), block_num);
    assert!(result.is_some(), "storage_map_entries should return Some for empty maps");

    let details = result.unwrap();
    assert_eq!(details.slot_name, slot_name);
    match details.entries {
        StorageMapEntries::AllEntries(entries) => {
            assert!(entries.is_empty(), "entries should be empty for an empty map");
        },
        StorageMapEntries::LimitExceeded => {
            panic!("should not exceed limit for empty map");
        },
        StorageMapEntries::EntriesWithProofs(_) => {
            panic!("should not have proofs for empty map query");
        },
    }
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
    let result = forest.open_storage_map(account_id, slot_name.clone(), block_num, &keys);

    let details = result.expect("Should return Some").expect("Should not error");
    assert_matches!(details.entries, StorageMapEntries::EntriesWithProofs(entries) => {
        assert_eq!(entries.len(), keys.len());
    });
}

// PRUNING TESTS
// ================================================================================================

const TEST_CHAIN_LENGTH: u32 = 100;
const TEST_AMOUNT_MULTIPLIER: u32 = 100;
const TEST_PRUNE_CHAIN_TIP: u32 = HISTORICAL_BLOCK_RETENTION + 5;

#[test]
fn prune_handles_empty_forest() {
    let mut forest = InnerForest::new();

    let (vault_removed, storage_roots_removed, storage_entries_removed) =
        forest.prune(BlockNumber::GENESIS);

    assert_eq!(vault_removed, 0);
    assert_eq!(storage_roots_removed, 0);
    assert_eq!(storage_entries_removed, 0); // Always 0 now (LRU cache)
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
    let vault_root_retained = forest.vault_roots[&(account_id, retained_block)];
    let vault_root_pruned = forest.vault_roots[&(account_id, pruned_block)];
    let storage_root_pruned =
        forest.storage_map_roots[&(account_id, slot_name.clone(), pruned_block)];

    let (vault_removed, storage_roots_removed, storage_entries_removed) =
        forest.prune(retained_block);

    assert!(vault_removed > 0);
    assert!(storage_roots_removed > 0);
    assert_eq!(storage_entries_removed, 0); // Cache is LRU, not counted
    assert!(forest.vault_roots.contains_key(&(account_id, retained_block)));
    assert!(!forest.vault_roots.contains_key(&(account_id, pruned_block)));
    assert!(!forest.storage_map_roots.contains_key(&(account_id, slot_name, pruned_block)));

    let asset_key: Word = FungibleAsset::new(faucet_id, 0).unwrap().vault_key().into();
    assert_matches!(forest.forest.open(vault_root_retained, asset_key), Ok(_));
    assert_matches!(forest.forest.open(vault_root_pruned, asset_key), Err(_));

    let storage_key = StorageMap::hash_key(Word::from([1u32, 0, 0, 0]));
    assert_matches!(forest.forest.open(storage_root_pruned, storage_key), Err(_));
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

    let (vault_removed, storage_roots_removed, storage_entries_removed) =
        forest.prune(BlockNumber::from(HISTORICAL_BLOCK_RETENTION));

    assert_eq!(vault_removed, 0);
    assert_eq!(storage_roots_removed, 0);
    assert_eq!(storage_entries_removed, 0);
    assert_eq!(forest.vault_roots.len(), HISTORICAL_BLOCK_RETENTION as usize);
}

#[test]
fn prune_vault_roots_removes_old_entries() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let amount = (i * TEST_AMOUNT_MULTIPLIER).into();
        let mut vault_delta = AccountVaultDelta::default();
        vault_delta.add_asset(dummy_fungible_asset(faucet_id, amount)).unwrap();
        let delta = dummy_partial_delta(account_id, vault_delta, AccountStorageDelta::default());
        forest.update_account(block_num, &delta).unwrap();
    }

    assert_eq!(forest.vault_roots.len(), TEST_CHAIN_LENGTH as usize);

    let (vault_removed, ..) = forest.prune(BlockNumber::from(TEST_CHAIN_LENGTH));

    let expected_removed = (TEST_CHAIN_LENGTH - HISTORICAL_BLOCK_RETENTION - 1) as usize;
    assert_eq!(vault_removed, expected_removed);

    let expected_remaining = (HISTORICAL_BLOCK_RETENTION + 1) as usize;
    assert_eq!(forest.vault_roots.len(), expected_remaining);

    let remaining_blocks = Vec::from_iter(forest.vault_roots.keys().map(|(_, b)| b.as_u32()));
    let oldest_remaining = *remaining_blocks.iter().min().unwrap();
    let expected_oldest = TEST_CHAIN_LENGTH - HISTORICAL_BLOCK_RETENTION;
    assert_eq!(oldest_remaining, expected_oldest);
}

#[test]
fn prune_storage_map_roots_removes_old_entries() {
    use miden_protocol::account::delta::StorageMapDelta;

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let slot_name = StorageSlotName::mock(3);

    for i in 1..=TEST_CHAIN_LENGTH {
        let block_num = BlockNumber::from(i);
        let key = Word::from([i, i * i, 5, 4]);
        let value = Word::from([0, 0, i * i * i, 77]);

        let mut map_delta = StorageMapDelta::default();
        map_delta.insert(key, value);
        let asd = AccountStorageDelta::new().add_updated_maps([(slot_name.clone(), map_delta)]);
        let delta = dummy_partial_delta(account_id, AccountVaultDelta::default(), asd);
        forest.update_account(block_num, &delta).unwrap();
    }

    assert_eq!(forest.storage_map_roots.len(), TEST_CHAIN_LENGTH as usize);

    let (_, storage_roots_removed, storage_entries_removed) =
        forest.prune(BlockNumber::from(TEST_CHAIN_LENGTH));

    let expected_removed = (TEST_CHAIN_LENGTH - HISTORICAL_BLOCK_RETENTION - 1) as usize;
    assert_eq!(storage_roots_removed, expected_removed);
    assert_eq!(storage_entries_removed, 0); // Cache is LRU, not counted

    let expected_remaining = (HISTORICAL_BLOCK_RETENTION + 1) as usize;
    assert_eq!(forest.storage_map_roots.len(), expected_remaining);
    // Cache size: LRU may have evicted entries, just verify it's populated
    assert!(!forest.storage_entries_per_user_block_slot.is_empty());
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

    assert_eq!(forest.vault_roots.len(), (TEST_CHAIN_LENGTH * 2) as usize);

    let (vault_removed, ..) = forest.prune(BlockNumber::from(TEST_CHAIN_LENGTH));

    let expected_removed_per_account =
        (TEST_CHAIN_LENGTH - HISTORICAL_BLOCK_RETENTION - 1) as usize;
    assert_eq!(vault_removed, expected_removed_per_account * 2);

    let expected_remaining_per_account = (HISTORICAL_BLOCK_RETENTION + 1) as usize;
    let account1_entries = forest.vault_roots.keys().filter(|(id, _)| *id == account1).count();
    let account2_entries = forest.vault_roots.keys().filter(|(id, _)| *id == account2).count();
    assert_eq!(account1_entries, expected_remaining_per_account);
    assert_eq!(account2_entries, expected_remaining_per_account);
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

    assert_eq!(forest.storage_map_roots.len(), (TEST_CHAIN_LENGTH * 2) as usize);

    let chain_tip = BlockNumber::from(TEST_CHAIN_LENGTH);
    let (_, storage_roots_removed, storage_entries_removed) = forest.prune(chain_tip);

    let cutoff = TEST_CHAIN_LENGTH - HISTORICAL_BLOCK_RETENTION;
    let expected_removed_per_slot = cutoff - 1;
    let expected_removed = expected_removed_per_slot * 2;
    assert_eq!(storage_roots_removed, expected_removed as usize);
    assert_eq!(storage_entries_removed, 0); // Cache is LRU, not counted

    let expected_remaining = HISTORICAL_BLOCK_RETENTION + 1;
    assert_eq!(forest.storage_map_roots.len(), (expected_remaining * 2) as usize);
    // Cache contains 2 latest entries (one per slot)
    assert_eq!(forest.storage_entries_per_user_block_slot.len(), 2);
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
    let (vault_removed, storage_roots_removed, storage_entries_removed) = forest.prune(block_100);

    // Vault at block 1 preserved (most recent)
    assert_eq!(vault_removed, 0);
    assert!(forest.vault_roots.contains_key(&(account_id, block_1)));

    // map_a: Block 51 preserved, block 1 pruned
    assert!(
        forest
            .storage_map_roots
            .contains_key(&(account_id, slot_map_a.clone(), block_at_51))
    );
    assert!(!forest.storage_map_roots.contains_key(&(account_id, slot_map_a, block_1)));

    // map_b: Block 1 preserved (most recent)
    assert!(forest.storage_map_roots.contains_key(&(account_id, slot_map_b, block_1)));

    assert_eq!(storage_roots_removed, 1);
    assert_eq!(storage_entries_removed, 0); // Cache is LRU, not counted
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
    let (vault_removed, storage_roots_removed, _) = forest.prune(block_100);

    // Blocks 1 and 25 pruned (outside retention, have newer entries)
    assert_eq!(vault_removed, 2);
    assert_eq!(storage_roots_removed, 2);

    // Verify preserved entries
    assert!(!forest.vault_roots.contains_key(&(account_id, BlockNumber::from(1))));
    assert!(!forest.vault_roots.contains_key(&(account_id, BlockNumber::from(25))));
    assert!(forest.vault_roots.contains_key(&(account_id, BlockNumber::from(50))));
    assert!(forest.vault_roots.contains_key(&(account_id, BlockNumber::from(75))));
    assert!(forest.vault_roots.contains_key(&(account_id, BlockNumber::from(100))));
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
    let root1_at_block1 = forest.vault_roots[&(account1, block_1)];
    let root2_at_block1 = forest.vault_roots[&(account2, block_1)];
    assert_eq!(root1_at_block1, root2_at_block1, "identical vaults should have identical roots");

    // Block 2: Only account2 changes (adds more assets)
    let block_2 = block_1.child();
    let mut vault_delta_2_update = AccountVaultDelta::default();
    vault_delta_2_update.add_asset(dummy_fungible_asset(faucet_id, 500)).unwrap();
    let delta_2_update =
        dummy_partial_delta(account2, vault_delta_2_update, AccountStorageDelta::default());
    forest.update_account(block_2, &delta_2_update).unwrap();

    // Account2 now has a different root
    let root2_at_block2 = forest.vault_roots[&(account2, block_2)];
    assert_ne!(root2_at_block1, root2_at_block2, "account2 vault should have changed");

    // Account1 has no entry at block 2, but lookup should still return block 1's root
    assert!(!forest.vault_roots.contains_key(&(account1, block_2)));
    let root1_lookup = forest.get_vault_root(account1, block_2);
    assert_eq!(
        root1_lookup,
        Some(root1_at_block1),
        "account1 should still resolve to block 1 root"
    );

    // Account1 should still be able to generate witnesses at block 2 (using block 1's data)
    let witnesses = forest
        .get_vault_asset_witnesses(account1, block_2, [asset_key].into())
        .expect("witness generation should succeed for unchanged account");
    assert_eq!(witnesses.len(), 1);

    // The proof should verify against the original root
    let proof: SmtProof = witnesses[0].clone().into();
    assert_eq!(proof.compute_root(), root1_at_block1);
}
