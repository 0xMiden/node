use miden_protocol::account::{AccountCodePatch, StorageMapPatchEntries, StorageValuePatch};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

use super::*;

fn save(db: &TestDb, account: &Account, patch: AccountPatch, block: u32, new: bool) {
    let block = BlockNumber::from(block);
    insert_block_header(db, block);
    upsert_accounts(
        db,
        &[block_account_update(
            account.id(),
            account.to_commitment(),
            AccountUpdateDetails::Public(patch),
        )],
        block,
        &precomputed_states_from_account(account),
        &if new {
            BTreeSet::from([account.id()])
        } else {
            BTreeSet::new()
        },
    )
    .unwrap();
}

#[test]
fn private_account_updates_leave_size_counters_null() {
    let db = TestDb::new();
    let account = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );
    for block in 0..2_u32 {
        insert_block_header(&db, block.into());
        upsert_accounts(
            &db,
            &[block_account_update(
                account,
                Word::from([block + 1, 0, 0, 0]),
                AccountUpdateDetails::Private,
            )],
            block.into(),
            &PrecomputedPublicAccountStates::new(),
            &if block == 0 {
                BTreeSet::from([account])
            } else {
                BTreeSet::new()
            },
        )
        .unwrap();
        assert_eq!(
            db.read(move |tx| queries::select_account_size(tx, account, block.into()))
                .unwrap(),
            None,
        );
    }
    let counts = db.read(move |tx| {
        tx.query(
            "SELECT storage_slots, storage_map_entries, vault_assets FROM accounts WHERE account_id = ?1",
            &[&account],
            |row| Ok((row.get::<Option<i64>>(0)?, row.get::<Option<i64>>(1)?, row.get::<Option<i64>>(2)?)),
        )
    }).unwrap();
    assert_eq!(counts, vec![(None, None, None); 2]);
}

#[test]
fn account_sizes_track_replacements_deletions_and_reinsertions() {
    let db = TestDb::new();
    let slot = StorageSlotName::mock(0);
    let key = StorageMapKey::new(Word::from([1u32, 0, 0, 0]));
    let faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let asset_id = FungibleAsset::new(faucet, 1).unwrap().id();
    let mut account = create_account_with_map_storage(slot.clone(), vec![]);
    let account_id = account.id();
    let storage_slots = account.storage().slots().len() as u64;
    save(&db, &account, AccountPatch::try_from(account.clone()).unwrap(), 0, true);

    // Replacing a value preserves its count; repeated deletion and reinsertion must also account
    // for the tombstone left by the first deletion.
    for (block, amount) in [(1, 10), (2, 20), (3, 0), (4, 0), (5, 30)] {
        let asset = if amount == 0 {
            Word::empty()
        } else {
            Asset::from(FungibleAsset::new(faucet, amount).unwrap()).to_value_word()
        };
        let patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::from_entries([(
                slot.clone(),
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([(
                        key,
                        Word::from([amount as u32, 0, 0, 0]),
                    )])),
                }),
            )])
            .unwrap(),
            AccountVaultPatch::new(BTreeMap::from([(asset_id, asset)])).unwrap(),
            AccountCodePatch::default(),
            Some(Felt::new_unchecked(u64::from(block) + 1)),
        )
        .unwrap();
        account.apply_patch(&patch).unwrap();
        save(&db, &account, patch, block, false);
    }

    for (block, entries) in [(0, 0), (1, 1), (2, 1), (3, 0), (4, 0), (5, 1)] {
        let size = db
            .read(move |tx| queries::select_account_size(tx, account_id, block.into()))
            .unwrap()
            .unwrap();
        assert_eq!(
            size,
            queries::AccountSize {
                storage_slots,
                storage_map_entries: entries,
                vault_assets: entries,
            },
            "incorrect account size at block {block}"
        );
        let state = db
            .read(move |tx| queries::load_full_account_at(tx, account_id, block.into()))
            .unwrap();
        assert_eq!(state.maps.get(&slot).map_or(0, BTreeMap::len) as u64, entries);
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Keeps historical size assertions with their sequence of committed account updates."
)]
fn account_sizes_follow_live_state_and_preserve_historical_counts() {
    let db = TestDb::new();
    let slot = StorageSlotName::mock(0);
    let key = |n: u32| StorageMapKey::new(Word::from([n, 0, 0, 0]));
    let value = |n: u32| Word::from([n, 0, 0, 0]);
    let mut account =
        create_account_with_map_storage(slot.clone(), vec![(key(1), value(1)), (key(2), value(2))]);
    save(&db, &account, AccountPatch::try_from(account.clone()).unwrap(), 0, true);
    let account_id = account.id();
    let original_slots = account.storage().slots().len() as u64;
    let initial = db
        .read(move |tx| queries::select_account_size(tx, account_id, 0.into()))
        .unwrap()
        .unwrap();
    assert_eq!(
        initial,
        queries::AccountSize {
            storage_slots: original_slots,
            storage_map_entries: 2,
            vault_assets: 0
        }
    );

    let asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 17)
            .unwrap()
            .into();
    let patch = AccountPatch::new(
        account_id,
        AccountStoragePatch::from_entries([(
            slot.clone(),
            StorageSlotPatch::Map(StorageMapPatch::Update {
                entries: StorageMapPatchEntries::from_raw(BTreeMap::from([
                    (key(1), Word::empty()),
                    (key(2), value(22)),
                    (key(3), value(3)),
                ])),
            }),
        )])
        .unwrap(),
        AccountVaultPatch::new(BTreeMap::from([(asset.id(), asset.to_value_word())])).unwrap(),
        AccountCodePatch::default(),
        Some(Felt::new_unchecked(2)),
    )
    .unwrap();
    account.apply_patch(&patch).unwrap();
    save(&db, &account, patch, 1, false);
    let size = db
        .read(move |tx| queries::select_account_size(tx, account_id, 1.into()))
        .unwrap()
        .unwrap();
    assert_eq!(size, queries::AccountSize { vault_assets: 1, ..initial });

    let patch = AccountPatch::new(
        account_id,
        AccountStoragePatch::from_entries([(
            slot.clone(),
            StorageSlotPatch::Map(StorageMapPatch::Remove),
        )])
        .unwrap(),
        AccountVaultPatch::new(BTreeMap::from([(asset.id(), Word::empty())])).unwrap(),
        AccountCodePatch::default(),
        Some(Felt::new_unchecked(3)),
    )
    .unwrap();
    account.apply_patch(&patch).unwrap();
    save(&db, &account, patch, 2, false);
    let size = db
        .read(move |tx| queries::select_account_size(tx, account_id, 2.into()))
        .unwrap()
        .unwrap();
    assert_eq!(
        size,
        queries::AccountSize {
            storage_slots: original_slots - 1,
            storage_map_entries: 0,
            vault_assets: 0
        }
    );

    let patch = AccountPatch::new(
        account_id,
        AccountStoragePatch::from_entries([
            (
                slot.clone(),
                StorageSlotPatch::Map(StorageMapPatch::Create {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([(key(4), value(4))])),
                }),
            ),
            (
                StorageSlotName::mock(7),
                StorageSlotPatch::Value(StorageValuePatch::Create { value: value(7) }),
            ),
        ])
        .unwrap(),
        AccountVaultPatch::default(),
        AccountCodePatch::default(),
        Some(Felt::new_unchecked(4)),
    )
    .unwrap();
    account.apply_patch(&patch).unwrap();
    save(&db, &account, patch, 3, false);
    let size = db
        .read(move |tx| queries::select_account_size(tx, account_id, 3.into()))
        .unwrap()
        .unwrap();
    let state = db
        .read(move |tx| queries::load_full_account_at(tx, account_id, 3.into()))
        .unwrap();
    assert_eq!(
        size,
        queries::AccountSize {
            storage_slots: original_slots + 1,
            storage_map_entries: 1,
            vault_assets: 0
        }
    );
    assert_eq!(state.maps[&slot], BTreeMap::from([(key(4), value(4))]));
    assert_eq!(
        db.read(move |tx| queries::select_account_size(tx, account_id, 0.into()))
            .unwrap(),
        Some(initial)
    );
    assert_eq!(
        db.read(move |tx| queries::select_account_size(tx, account_id, 1.into()))
            .unwrap()
            .unwrap()
            .vault_assets,
        1
    );
}
