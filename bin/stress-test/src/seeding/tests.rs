use miden_protocol::account::StorageSlotContent;

use super::*;

fn benchmark_fungible_faucet_ids(vault_entries: usize) -> Vec<AccountId> {
    create_benchmark_faucets(vault_entries)
        .into_iter()
        .map(|account| account.id())
        .collect()
}

#[test]
fn public_account_can_be_created_with_large_storage_map() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let mut rng = RandomCoin::new(coin_seed.into());
    let key_pair = SecretKey::with_rng(&mut rng);

    let account = create_account(key_pair.public_key(), 42, AccountStorageMode::Public, 128);

    let map_slot = account
        .storage()
        .slots()
        .iter()
        .find(|slot| slot.name() == &benchmark_storage_map_slot())
        .expect("benchmark storage map slot should exist");

    let StorageSlotContent::Map(storage_map) = map_slot.content() else {
        panic!("benchmark slot should be a storage map");
    };

    assert_eq!(storage_map.num_entries(), 128);
}

#[test]
fn private_account_ignores_large_storage_map_entries() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let mut rng = RandomCoin::new(coin_seed.into());
    let key_pair = SecretKey::with_rng(&mut rng);

    let account = create_account(key_pair.public_key(), 42, AccountStorageMode::Private, 128);

    assert!(
        account
            .storage()
            .slots()
            .iter()
            .all(|slot| slot.name() != &benchmark_storage_map_slot())
    );
}

#[test]
fn public_account_note_contains_requested_distinct_vault_assets() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let rng = Arc::new(Mutex::new(RandomCoin::new(coin_seed.into())));
    let mut key_rng = rng.lock().unwrap();
    let key_pair = SecretKey::with_rng(&mut *key_rng);
    drop(key_rng);

    let faucet_ids = benchmark_fungible_faucet_ids(5);
    let (_, notes) = create_accounts_and_notes(
        1,
        AccountStorageMode::Public,
        &key_pair,
        &rng,
        &faucet_ids,
        0,
        0,
        5,
    );

    let assets = notes[0].assets();
    assert_eq!(assets.num_assets(), 5);

    let distinct_vault_keys =
        assets.iter().map(Asset::vault_key).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct_vault_keys.len(), 5);
}

#[test]
fn private_account_note_keeps_single_vault_asset() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let rng = Arc::new(Mutex::new(RandomCoin::new(coin_seed.into())));
    let mut key_rng = rng.lock().unwrap();
    let key_pair = SecretKey::with_rng(&mut *key_rng);
    drop(key_rng);

    let faucet_ids = benchmark_fungible_faucet_ids(5);
    let (_, notes) = create_accounts_and_notes(
        1,
        AccountStorageMode::Private,
        &key_pair,
        &rng,
        &faucet_ids,
        0,
        0,
        5,
    );

    assert_eq!(notes[0].assets().num_assets(), 1);
}

#[test]
fn public_account_storage_map_entry_can_be_updated_for_benchmark_blocks() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let mut rng = RandomCoin::new(coin_seed.into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let mut account = create_account(key_pair.public_key(), 42, AccountStorageMode::Public, 4);

    let key = StorageMapKey::from_index(2);
    let old_value = account
        .storage()
        .get_map_item(&benchmark_storage_map_slot(), key.into())
        .unwrap();

    let updated = update_benchmark_storage_map_entry(&mut account, 3, 9, 4);

    let new_value = account
        .storage()
        .get_map_item(&benchmark_storage_map_slot(), key.into())
        .unwrap();
    assert!(updated);
    assert_ne!(new_value, old_value);
    assert_eq!(new_value, benchmark_storage_map_update_value(3, 9, 2));
}

#[test]
fn private_account_storage_map_update_is_skipped() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let mut rng = RandomCoin::new(coin_seed.into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let mut account = create_account(key_pair.public_key(), 42, AccountStorageMode::Private, 4);

    let updated = update_benchmark_storage_map_entry(&mut account, 3, 9, 4);

    assert!(!updated);
}
