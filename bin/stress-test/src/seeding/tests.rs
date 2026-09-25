use miden_protocol::account::StorageSlotContent;

use super::*;

fn benchmark_fungible_faucet_ids(vault_entries: usize) -> Vec<AccountId> {
    create_benchmark_faucets(vault_entries)
        .into_iter()
        .map(|account| account.id())
        .collect()
}

#[test]
fn account_batches_honor_the_exact_requested_count() {
    assert_eq!(
        plan_account_batches(1, 100, ACCOUNT_UPDATES_PER_BLOCK),
        vec![AccountBatch { public: 1, private: 0 }]
    );
    assert_eq!(
        plan_account_batches(254, 50, ACCOUNT_UPDATES_PER_BLOCK),
        vec![AccountBatch { public: 127, private: 127 }]
    );
    assert_eq!(
        plan_account_batches(255, 50, ACCOUNT_UPDATES_PER_BLOCK),
        vec![AccountBatch { public: 128, private: 127 }]
    );
    assert_eq!(
        plan_account_batches(256, 50, ACCOUNT_UPDATES_PER_BLOCK),
        vec![
            AccountBatch { public: 128, private: 127 },
            AccountBatch { public: 0, private: 1 },
        ]
    );
}

#[test]
fn account_batches_distribute_public_accounts_across_partial_batches() {
    let batches = plan_account_batches(1_000, 37, ACCOUNT_UPDATES_PER_BLOCK);

    assert!(batches.iter().all(|batch| batch.public + batch.private <= 255));
    assert_eq!(batches.iter().map(|batch| batch.public).sum::<usize>(), 370);
    assert_eq!(batches.iter().map(|batch| batch.private).sum::<usize>(), 630);
}

#[test]
fn oversized_account_updates_are_seeded_at_genesis() {
    assert!(!account_update_may_exceed_protocol_limit(128, 1));
    assert!(account_update_may_exceed_protocol_limit(4_096, 1));
    assert!(account_update_may_exceed_protocol_limit(250_000, 1));
}

#[test]
fn public_account_can_be_created_with_large_storage_map() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let mut rng = RandomCoin::new(coin_seed.into());
    let key_pair = SecretKey::with_rng(&mut rng);

    let account = create_account(key_pair.public_key(), 42, AccountType::Public, 128);

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

    let account = create_account(key_pair.public_key(), 42, AccountType::Private, 128);

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
    let (_, notes) =
        create_accounts_and_notes(1, AccountType::Public, &key_pair, &rng, &faucet_ids, 0, 0, 5);

    let assets = notes[0].assets();
    assert_eq!(assets.num_assets(), 5);

    let distinct_vault_keys =
        assets.iter().map(Asset::id).collect::<std::collections::BTreeSet<_>>();
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
    let (_, notes) =
        create_accounts_and_notes(1, AccountType::Private, &key_pair, &rng, &faucet_ids, 0, 0, 5);

    assert_eq!(notes[0].assets().num_assets(), 1);
}

#[test]
fn public_account_storage_map_entry_can_be_updated_for_benchmark_blocks() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let mut rng = RandomCoin::new(coin_seed.into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let mut account = create_account(key_pair.public_key(), 42, AccountType::Public, 4);

    let key = StorageMapKey::from_index(2);
    let old_value = account.storage().get_map_item(&benchmark_storage_map_slot(), key).unwrap();

    let updated = update_benchmark_storage_map_entry(&mut account, 3, 9, 4);

    let new_value = account.storage().get_map_item(&benchmark_storage_map_slot(), key).unwrap();
    assert!(updated);
    assert_ne!(new_value, old_value);
    assert_eq!(new_value, benchmark_storage_map_update_value(3, 9, 2));
}

#[test]
fn private_account_storage_map_update_is_skipped() {
    let coin_seed = [1, 2, 3, 4].map(Felt::new_unchecked);
    let mut rng = RandomCoin::new(coin_seed.into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let mut account = create_account(key_pair.public_key(), 42, AccountType::Private, 4);

    let updated = update_benchmark_storage_map_entry(&mut account, 3, 9, 4);

    assert!(!updated);
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_store_persists_one_public_account_and_applies_one_map_update() {
    use miden_node_proto::domain::account::{
        AccountDetailRequest,
        AccountStorageRequest,
        GetAccountRequest,
        StorageMapEntries,
    };

    let temp_dir = tempfile::tempdir().unwrap();
    let data_directory = temp_dir.path().join("store");
    seed_store(data_directory.clone(), 1, 100, 4, 1, 1).await;

    let account_ids = fs_err::read_to_string(data_directory.join(ACCOUNTS_FILENAME)).unwrap();
    let account_ids = account_ids.lines().collect::<Vec<_>>();
    assert_eq!(account_ids.len(), 1);
    let account_id = AccountId::from_hex(account_ids[0]).unwrap();

    let (state, block_writer, writer_task) = load_state(data_directory).await;
    let response = state
        .view()
        .get_account(GetAccountRequest {
            account_id,
            block_num: None,
            details: Some(AccountDetailRequest {
                code_commitment: None,
                asset_vault_commitment: None,
                storage_request: AccountStorageRequest::AllStorageMaps,
            }),
        })
        .await
        .unwrap();
    let details = response.details.expect("public account details should be returned");
    assert_eq!(details.storage_details.map_details.len(), 1);
    let map_details = &details.storage_details.map_details[0];
    assert_eq!(map_details.slot_name, benchmark_storage_map_slot());
    let StorageMapEntries::AllEntries(entries) = &map_details.entries else {
        panic!("small benchmark map should return all entries");
    };
    assert_eq!(entries.len(), 4);
    assert_eq!(
        entries
            .iter()
            .find(|(key, _)| *key == StorageMapKey::from_index(1))
            .map(|(_, value)| *value),
        Some(benchmark_storage_map_update_value(0, 0, 1))
    );

    // Release the backing storage before the temporary directory is deleted.
    drop(state);
    block_writer.stop(writer_task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_store_handles_map_larger_than_transaction_account_update_limit() {
    use miden_node_proto::domain::account::GetAccountRequest;

    let temp_dir = tempfile::tempdir().unwrap();
    let data_directory = temp_dir.path().join("store");
    seed_store(data_directory.clone(), 1, 100, 4_096, 1, 1).await;

    let account_ids = fs_err::read_to_string(data_directory.join(ACCOUNTS_FILENAME)).unwrap();
    let account_ids = account_ids.lines().collect::<Vec<_>>();
    assert_eq!(account_ids.len(), 1);
    let account_id = AccountId::from_hex(account_ids[0]).unwrap();

    let (state, block_writer, writer_task) = load_state(data_directory).await;
    let response = state
        .view()
        .get_account(GetAccountRequest {
            account_id,
            block_num: None,
            details: None,
        })
        .await
        .unwrap();
    assert_ne!(response.witness.state_commitment(), Word::empty());

    // Release the backing storage before the temporary directory is deleted.
    drop(state);
    block_writer.stop(writer_task).await;
}
