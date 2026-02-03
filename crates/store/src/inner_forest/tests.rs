use miden_protocol::account::AccountCode;
use miden_protocol::asset::{Asset, AssetVault, FungibleAsset};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
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
    // For partial deltas, nonce_delta must be > 0 if there are changes
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

    // Create a minimal account with the given assets
    let vault = AssetVault::new(assets).unwrap();
    let storage = AccountStorage::new(vec![]).unwrap();
    let code = AccountCode::mock();
    let nonce = Felt::ONE;

    let account = Account::new(account_id, vault, storage, code, nonce, None).unwrap();

    // Convert to delta - this will be a full-state delta because it has code
    AccountDelta::try_from(account).unwrap()
}

#[test]
fn test_empty_smt_root_is_recognized() {
    use miden_protocol::crypto::merkle::smt::Smt;

    let empty_root = InnerForest::empty_smt_root();

    // Verify an empty SMT has the expected root
    assert_eq!(Smt::default().root(), empty_root);

    // Test that SmtForest accepts this root in batch_insert
    let mut forest = SmtForest::new();
    let entries = vec![(Word::from([1u32, 2, 3, 4]), Word::from([5u32, 6, 7, 8]))];

    assert!(forest.batch_insert(empty_root, entries).is_ok());
}

#[test]
fn test_inner_forest_basic_initialization() {
    let forest = InnerForest::new();
    assert!(forest.storage_map_roots.is_empty());
    assert!(forest.vault_roots.is_empty());
}

#[test]
fn test_update_account_with_empty_deltas() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    let delta = dummy_partial_delta(
        account_id,
        AccountVaultDelta::default(),
        AccountStorageDelta::default(),
    );

    forest.update_account(block_num, &delta).unwrap();

    // Empty deltas should not create entries
    assert!(!forest.vault_roots.contains_key(&(account_id, block_num)));
    assert!(forest.storage_map_roots.is_empty());
}

#[test]
fn test_update_vault_with_fungible_asset() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let block_num = BlockNumber::GENESIS.child();

    let asset = dummy_fungible_asset(faucet_id, 100);
    let mut vault_delta = AccountVaultDelta::default();
    vault_delta.add_asset(asset).unwrap();

    let delta = dummy_partial_delta(account_id, vault_delta, AccountStorageDelta::default());
    forest.update_account(block_num, &delta).unwrap();

    let vault_root = forest.vault_roots[&(account_id, block_num)];
    assert_ne!(vault_root, EMPTY_WORD);
}

#[test]
fn test_compare_partial_vs_full_state_delta_vault() {
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();
    let block_num = BlockNumber::GENESIS.child();
    let asset = dummy_fungible_asset(faucet_id, 100);

    // Approach 1: Partial delta (simulates block application)
    let mut forest_partial = InnerForest::new();
    let mut vault_delta = AccountVaultDelta::default();
    vault_delta.add_asset(asset).unwrap();
    let partial_delta =
        dummy_partial_delta(account_id, vault_delta, AccountStorageDelta::default());
    forest_partial.update_account(block_num, &partial_delta).unwrap();

    // Approach 2: Full-state delta (simulates DB reconstruction)
    let mut forest_full = InnerForest::new();
    let full_delta = dummy_full_state_delta(account_id, &[asset]);
    forest_full.update_account(block_num, &full_delta).unwrap();

    // Both approaches must produce identical vault roots
    let root_partial = forest_partial.vault_roots.get(&(account_id, block_num)).unwrap();
    let root_full = forest_full.vault_roots.get(&(account_id, block_num)).unwrap();

    assert_eq!(root_partial, root_full);
    assert_ne!(*root_partial, EMPTY_WORD);
}

#[test]
fn test_incremental_vault_updates() {
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    // Block 1: 100 tokens
    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 100)).unwrap();
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();
    let root_1 = forest.vault_roots[&(account_id, block_1)];

    // Block 2: 150 tokens (update)
    let block_2 = block_1.child();
    let mut vault_delta_2 = AccountVaultDelta::default();
    vault_delta_2.add_asset(dummy_fungible_asset(faucet_id, 150)).unwrap();
    let delta_2 = dummy_partial_delta(account_id, vault_delta_2, AccountStorageDelta::default());
    forest.update_account(block_2, &delta_2).unwrap();
    let root_2 = forest.vault_roots[&(account_id, block_2)];

    assert_ne!(root_1, root_2);
}

#[test]
fn test_vault_state_persists_across_blocks_without_changes() {
    // Regression test for issue #7: vault state should persist across blocks
    // where no changes occur, not reset to empty.
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    // Helper to query vault root at or before a block (range query)
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

    // Blocks 2-5: No changes to this account (simulated by not calling update_account)
    // This means no entries are added to vault_roots for these blocks.

    // Block 6: Add 50 more tokens
    // The previous root lookup should find block_1's root, not return empty.
    let block_6 = BlockNumber::from(6);
    let mut vault_delta_6 = AccountVaultDelta::default();
    vault_delta_6.add_asset(dummy_fungible_asset(faucet_id, 150)).unwrap(); // 100 + 50 = 150
    let delta_6 = dummy_partial_delta(account_id, vault_delta_6, AccountStorageDelta::default());
    forest.update_account(block_6, &delta_6).unwrap();

    // The root at block 6 should be different from block 1 (we added more tokens)
    let root_after_block_6 = forest.vault_roots[&(account_id, block_6)];
    assert_ne!(root_after_block_1, root_after_block_6);

    // Verify range query finds the correct previous root for intermediate blocks
    // Block 3 should return block 1's root (most recent before block 3)
    let root_at_block_3 = get_vault_root(&forest, account_id, BlockNumber::from(3));
    assert_eq!(root_at_block_3, Some(root_after_block_1));

    // Block 5 should also return block 1's root
    let root_at_block_5 = get_vault_root(&forest, account_id, BlockNumber::from(5));
    assert_eq!(root_at_block_5, Some(root_after_block_1));

    // Block 6 should return block 6's root
    let root_at_block_6 = get_vault_root(&forest, account_id, block_6);
    assert_eq!(root_at_block_6, Some(root_after_block_6));
}

#[test]
fn test_partial_delta_applies_fungible_changes_correctly() {
    // Regression test for issue #8: partial deltas should apply changes to previous balance,
    // not treat amounts as absolute values.
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    // Block 1: Add 100 tokens (partial delta with +100)
    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 100)).unwrap();
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();
    let root_after_100 = forest.vault_roots[&(account_id, block_1)];

    // Block 2: Add 50 more tokens (partial delta with +50)
    // Result should be 150 tokens, not 50 tokens
    let block_2 = block_1.child();
    let mut vault_delta_2 = AccountVaultDelta::default();
    vault_delta_2.add_asset(dummy_fungible_asset(faucet_id, 50)).unwrap();
    let delta_2 = dummy_partial_delta(account_id, vault_delta_2, AccountStorageDelta::default());
    forest.update_account(block_2, &delta_2).unwrap();
    let root_after_150 = forest.vault_roots[&(account_id, block_2)];

    // Roots should be different (100 tokens vs 150 tokens)
    assert_ne!(root_after_100, root_after_150);

    // Block 3: Remove 30 tokens (partial delta with -30)
    // Result should be 120 tokens
    let block_3 = block_2.child();
    let mut vault_delta_3 = AccountVaultDelta::default();
    vault_delta_3.remove_asset(dummy_fungible_asset(faucet_id, 30)).unwrap();
    let delta_3 = dummy_partial_delta(account_id, vault_delta_3, AccountStorageDelta::default());
    forest.update_account(block_3, &delta_3).unwrap();
    let root_after_120 = forest.vault_roots[&(account_id, block_3)];

    // Root should change again
    assert_ne!(root_after_150, root_after_120);

    // Verify by creating a fresh forest with a full-state delta of 120 tokens
    // The roots should match
    let mut fresh_forest = InnerForest::new();
    let full_delta = dummy_full_state_delta(account_id, &[dummy_fungible_asset(faucet_id, 120)]);
    fresh_forest.update_account(block_3, &full_delta).unwrap();
    let root_full_state_120 = fresh_forest.vault_roots[&(account_id, block_3)];

    assert_eq!(root_after_120, root_full_state_120);
}

#[test]
fn test_partial_delta_across_long_block_range() {
    // Validation test: partial deltas should work across 101+ blocks.
    //
    // This test passes now because InnerForest keeps all history. Once pruning is implemented
    // (estimated ~50 blocks), this test will fail unless DB fallback is also implemented.
    // When that happens, the test should be updated to use DB fallback or converted to an
    // integration test that has DB access.
    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let faucet_id = dummy_faucet();

    // Block 1: Add 1000 tokens
    let block_1 = BlockNumber::GENESIS.child();
    let mut vault_delta_1 = AccountVaultDelta::default();
    vault_delta_1.add_asset(dummy_fungible_asset(faucet_id, 1000)).unwrap();
    let delta_1 = dummy_partial_delta(account_id, vault_delta_1, AccountStorageDelta::default());
    forest.update_account(block_1, &delta_1).unwrap();
    let root_after_1000 = forest.vault_roots[&(account_id, block_1)];

    // Blocks 2-100: No changes to this account (simulating long gap)

    // Block 101: Add 500 more tokens (partial delta with +500)
    // This requires looking up block 1's state across a 100-block gap.
    let block_101 = BlockNumber::from(101);
    let mut vault_delta_101 = AccountVaultDelta::default();
    vault_delta_101.add_asset(dummy_fungible_asset(faucet_id, 500)).unwrap();
    let delta_101 =
        dummy_partial_delta(account_id, vault_delta_101, AccountStorageDelta::default());
    forest.update_account(block_101, &delta_101).unwrap();
    let root_after_1500 = forest.vault_roots[&(account_id, block_101)];

    // Roots should be different (1000 tokens vs 1500 tokens)
    assert_ne!(root_after_1000, root_after_1500);

    // Verify the final state matches a fresh forest with 1500 tokens
    let mut fresh_forest = InnerForest::new();
    let full_delta = dummy_full_state_delta(account_id, &[dummy_fungible_asset(faucet_id, 1500)]);
    fresh_forest.update_account(block_101, &full_delta).unwrap();
    let root_full_state_1500 = fresh_forest.vault_roots[&(account_id, block_101)];

    assert_eq!(root_after_1500, root_full_state_1500);
}

#[test]
fn test_update_storage_map() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    let slot_name = StorageSlotName::mock(3);
    let key = Word::from([1u32, 2, 3, 4]);
    let value = Word::from([5u32, 6, 7, 8]);

    let mut map_delta = StorageMapDelta::default();
    map_delta.insert(key, value);
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta))]);
    let storage_delta = AccountStorageDelta::from_raw(raw);

    let delta = dummy_partial_delta(account_id, AccountVaultDelta::default(), storage_delta);
    forest.update_account(block_num, &delta).unwrap();

    // Verify storage root was created
    assert!(
        forest
            .storage_map_roots
            .contains_key(&(account_id, slot_name.clone(), block_num))
    );
    let storage_root = forest.storage_map_roots[&(account_id, slot_name, block_num)];
    assert_ne!(storage_root, InnerForest::empty_smt_root());
}

#[test]
fn test_full_state_delta_with_empty_vault_records_root() {
    // Regression test for issue #1581: full-state deltas with empty vaults must still record
    // the vault root so that subsequent `get_vault_asset_witnesses` calls succeed.
    //
    // The network counter account from the network monitor has an empty vault (it only uses
    // storage slots). Without this fix, `get_vault_asset_witnesses` fails with "root not found"
    // because no vault root was ever recorded for the account.
    use miden_protocol::account::{Account, AccountStorage};

    let mut forest = InnerForest::new();
    let account_id = dummy_account();
    let block_num = BlockNumber::GENESIS.child();

    // Create a full-state delta with an empty vault (like the network counter account).
    let vault = AssetVault::new(&[]).unwrap();
    let storage = AccountStorage::new(vec![]).unwrap();
    let code = AccountCode::mock();
    let nonce = Felt::ONE;
    let account = Account::new(account_id, vault, storage, code, nonce, None).unwrap();
    let full_delta = AccountDelta::try_from(account).unwrap();

    // Sanity check: the vault delta should be empty.
    assert!(full_delta.vault().is_empty());
    assert!(full_delta.is_full_state());

    forest.update_account(block_num, &full_delta).unwrap();

    // The vault root must be recorded even though the vault is empty.
    assert!(
        forest.vault_roots.contains_key(&(account_id, block_num)),
        "vault root should be recorded for full-state deltas with empty vaults"
    );

    // Verify the recorded root is the empty SMT root.
    let recorded_root = forest.vault_roots[&(account_id, block_num)];
    assert_eq!(
        recorded_root,
        InnerForest::empty_smt_root(),
        "empty vault should have the empty SMT root"
    );

    // Verify `get_vault_asset_witnesses` succeeds (returns empty witnesses for empty keys).
    let witnesses = forest
        .get_vault_asset_witnesses(account_id, block_num, std::collections::BTreeSet::new())
        .expect("get_vault_asset_witnesses should succeed for accounts with empty vaults");
    assert!(witnesses.is_empty());
}

#[test]
fn test_storage_map_incremental_updates() {
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

    // Block 2: Insert key2 -> value2 (key1 should persist)
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

    // All roots should be different
    assert_ne!(root_1, root_2);
    assert_ne!(root_2, root_3);
    assert_ne!(root_1, root_3);
}
