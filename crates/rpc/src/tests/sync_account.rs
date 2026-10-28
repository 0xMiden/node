use miden_protocol::Felt;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountCode,
    AccountCodePatch,
    AccountComponent,
    AccountHeader,
    AccountStorage,
    AccountStorageHeader,
    AccountStoragePatch,
    AccountVaultPatch,
    StorageMap,
    StorageMapKey,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlot,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
    StorageValuePatch,
};
use miden_protocol::asset::AssetVault;
use miden_protocol::block::account_tree::{AccountTree, AccountWitness};
use miden_protocol::block::{BlockAccountUpdate, BlockBody, BlockHeader};
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_standards::code_builder::CodeBuilder;
use proto::miden::node::v1::sync_account_response::Update;
use proto::miden::node::v1::{AccountSyncState, SyncAccountRequest, SyncAccountResponse};

use super::*;

fn account(entries: u32, assets: u32, code_version: u32) -> Account {
    let component = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code(
                "sync::test",
                format!("@account_procedure pub proc read push.{code_version} end"),
            )
            .unwrap(),
        vec![StorageSlot::with_map(
            StorageSlotName::mock(0),
            StorageMap::with_entries((0..entries).map(|n| (key(n), word(n + 1)))).unwrap(),
        )],
        AccountComponentMetadata::new("sync"),
    )
    .unwrap();
    AccountBuilder::new([91; 32])
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(NoopAuthComponent)
        .with_assets(vault_stream_values(assets).into_iter().map(|(_, asset)| asset.unwrap()))
        .build_existing()
        .unwrap()
}

fn word(n: u32) -> Word {
    Word::from([n, 0, 0, 0])
}
fn key(n: u32) -> StorageMapKey {
    StorageMapKey::new(word(n))
}

async fn fixture(account: &Account) -> (TestStore, ProvenBlock, ProtocolConfig) {
    let mut builder = MockChainBuilder::new();
    builder.add_account(account.clone()).unwrap();
    let chain = builder.build().unwrap();
    let genesis = chain.latest_block();
    let config = chain.protocol_config().clone();
    (TestStore::start_from_mock_genesis(&genesis, &config).await, genesis, config)
}

fn service(store: &TestStore, limit: u32) -> RpcService {
    service_with_config(
        store,
        crate::SyncAccountConfig {
            limit: std::num::NonZeroU32::new(limit).unwrap(),
            ..Default::default()
        },
    )
}

fn service_with_config(store: &TestStore, config: crate::SyncAccountConfig) -> RpcService {
    let mut rpc = RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::full_node(source_rpc_client(), None),
        None,
        NonZeroUsize::MIN,
        None,
    );
    rpc.set_sync_account_config(config);
    rpc
}

fn request(
    account: &Account,
    from: Option<u32>,
    target: u32,
    code: Option<Word>,
) -> Request<SyncAccountRequest> {
    Request::new(SyncAccountRequest {
        account_id: Some(account.id().into()),
        range: Some(proto::miden::node::v1::StateDeltaRange {
            from_block_exclusive: from,
            to_block_inclusive: Some(target),
        }),
        code_commitment: code.map(Into::into),
    })
}

fn payload(response: &SyncAccountResponse) -> (&AccountSyncState, bool) {
    match response.update.as_ref().unwrap() {
        Update::Snapshot(state) => (state, true),
        Update::Delta(state) => (state, false),
    }
}

/// Reconstructs state from the public response, retaining cached contents only for deltas.
fn reconstruct(
    response: SyncAccountResponse,
    starting_state: Option<&Account>,
    cached: &AccountCode,
) -> Account {
    let (state, full) = payload(&response);
    let header: AccountHeader =
        state.header.clone().unwrap().decode_fields().unwrap().verify().unwrap();
    let storage_header: AccountStorageHeader =
        state.storage_header.clone().unwrap().decode_fields().unwrap().verify().unwrap();
    let mut maps: BTreeMap<_, BTreeMap<StorageMapKey, Word>> = BTreeMap::new();
    let mut vault = BTreeMap::new();
    if !full {
        let old = starting_state.unwrap();
        for slot in old.storage().slots() {
            if let miden_protocol::account::StorageSlotContent::Map(map) = slot.content() {
                maps.insert(slot.name().clone(), map.entries().map(|(k, v)| (*k, *v)).collect());
            }
        }
        vault.extend(old.vault().assets().map(|asset| (asset.id(), asset.to_value_word())));
    }
    for map in &state.maps {
        let name: StorageSlotName = map.slot_name.parse().unwrap();
        let entries = maps.entry(name).or_default();
        for entry in &map.entries {
            let key: Word = entry.key.clone().unwrap().decode_fields().unwrap();
            let value: Word = entry.value.clone().unwrap().decode_fields().unwrap();
            if value == Word::empty() {
                entries.remove(&StorageMapKey::new(key));
            } else {
                entries.insert(StorageMapKey::new(key), value);
            }
        }
    }
    for entry in &state.vault {
        let key: Word = entry.asset_id.clone().unwrap().decode_fields().unwrap();
        let key: AssetId = key.try_into().unwrap();
        let value: Word = entry.value.clone().unwrap().decode_fields().unwrap();
        if value == Word::empty() {
            vault.remove(&key);
        } else {
            vault.insert(key, value);
        }
    }
    let storage = AccountStorage::new(
        storage_header
            .slots()
            .map(|slot| match slot.slot_type() {
                StorageSlotType::Value => {
                    StorageSlot::with_value(slot.name().clone(), slot.value())
                },
                StorageSlotType::Map => StorageSlot::with_map(
                    slot.name().clone(),
                    StorageMap::with_entries(maps.remove(slot.name()).unwrap_or_default()).unwrap(),
                ),
            })
            .collect(),
    )
    .unwrap();
    let assets = vault
        .into_iter()
        .map(|(id, value)| Asset::new(id, value).unwrap())
        .collect::<Vec<_>>();
    let code = response
        .code
        .map_or_else(|| cached.clone(), |code| code.decode_fields().unwrap().verify().unwrap());
    let account = Account::new(
        header.id(),
        AssetVault::new(&assets).unwrap(),
        storage,
        code,
        header.nonce(),
        None,
    )
    .unwrap();
    let witness: AccountWitness =
        response.witness.unwrap().decode_fields().unwrap().verify().unwrap();
    assert_eq!(account.to_commitment(), witness.state_commitment());
    account
}

async fn apply(
    store: &mut TestStore,
    genesis: &ProvenBlock,
    config: &ProtocolConfig,
    account: &mut Account,
    patch: AccountPatch,
) {
    account.apply_patch(&patch).unwrap();
    let root = AccountTree::with_entries(genesis.body().updated_accounts().iter().map(|item| {
        (
            item.account_id(),
            if item.account_id() == account.id() {
                account.to_commitment()
            } else {
                item.final_state_commitment()
            },
        )
    }))
    .unwrap()
    .root();
    let update = BlockAccountUpdate::new(
        account.id(),
        account.to_commitment(),
        AccountUpdateDetails::Public(patch),
    )
    .unwrap();
    let body = BlockBody::new(
        vec![update],
        vec![],
        vec![],
        miden_protocol::transaction::OrderedTransactionHeaders::new_unchecked(vec![]),
    )
    .unwrap();
    let base = next_block_with_protocol_config(store, config).await;
    let h = base.header();
    let header = BlockHeader::new(
        h.prev_block_commitment(),
        h.block_num(),
        h.chain_commitment(),
        root,
        h.nullifier_root(),
        body.compute_block_note_tree().root(),
        body.transaction_commitment(),
        h.validator_config().clone(),
        h.fee_parameters().clone(),
        h.protocol_config_commitment(),
        None,
        h.timestamp(),
    );
    store
        .writer
        .apply_block(
            SignedBlock::new_unchecked(header, body, BlockSignatures::new(vec![]).unwrap()),
            None,
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_snapshot_authenticates_contents_and_conditionally_returns_code() {
    let account = account(8, 2, 1);
    let (store, genesis, _) = fixture(&account).await;
    let rpc = service(&store, 11);
    for known in [None, Some(account.code().commitment()), Some(Word::empty())] {
        let response =
            rpc.sync_account(request(&account, None, 0, known)).await.unwrap().into_inner();
        assert!(payload(&response).1);
        assert_eq!(response.code.is_some(), known == Some(Word::empty()));
        let witness: AccountWitness =
            response.witness.clone().unwrap().decode_fields().unwrap().verify().unwrap();
        let leaf = witness.leaf();
        witness
            .path()
            .verify(leaf.index().position(), leaf.hash(), &genesis.header().account_root())
            .unwrap();
        assert_eq!(reconstruct(response, None, account.code()), account);
    }
    let response = rpc
        .sync_account(request(&account, Some(0), 0, None))
        .await
        .unwrap()
        .into_inner();
    assert!(!payload(&response).1);
    assert!(payload(&response).0.maps.is_empty());
    assert!(payload(&response).0.vault.is_empty());
    assert_eq!(reconstruct(response, Some(&account), account.code()), account);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_snapshot_preserves_empty_map_slots() {
    let account = account(0, 0, 1);
    let (store, ..) = fixture(&account).await;
    let rpc = service(&store, 1_000);
    let response = rpc.sync_account(request(&account, None, 0, None)).await.unwrap().into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(response, None, account.code()), account);
}

#[test]
fn sync_account_hides_internal_commitment_mismatch() {
    use miden_node_proto::domain::account as domain;

    let id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let witness = AccountTree::with_entries([(id, word(42))]).unwrap().open(id);
    let response = domain::SyncAccountResponse {
        block_num: 0.into(),
        witness,
        update: domain::AccountSyncUpdate::Snapshot(domain::AccountSyncState {
            header: AccountHeader::new(id, Felt::ONE, Word::empty(), Word::empty(), Word::empty()),
            storage_header: AccountStorageHeader::new(Vec::new()).unwrap(),
            maps: BTreeMap::new(),
            vault: BTreeMap::new(),
        }),
        code: None,
    };
    let error =
        <RpcService as miden_node_v1_node_service::SyncAccount>::encode(response).unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(error.details(), &[0]);
    assert_eq!(error.message(), "internal server error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_unchanged_account_returns_empty_delta_and_requested_code() {
    let account = account(8, 2, 1);
    let (mut store, _, config) = fixture(&account).await;
    let block = next_block_with_protocol_config(&store, &config).await;
    store.writer.apply_block(block, None).await.unwrap();
    let rpc = service(&store, 11);
    for known in [None, Some(account.code().commitment()), Some(Word::empty())] {
        let response = rpc
            .sync_account(request(&account, Some(0), 1, known))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.block_num, 1);
        assert!(!payload(&response).1);
        assert!(payload(&response).0.maps.is_empty());
        assert!(payload(&response).0.vault.is_empty());
        assert_eq!(response.code.is_some(), known == Some(Word::empty()));
        assert_eq!(reconstruct(response, Some(&account), account.code()), account);
    }

    let error = service(&store, 10)
        .sync_account(request(&account, Some(0), 1, None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    assert_eq!(error.details(), &[5]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_delta_reconciles_deletions_new_slots_and_code_upgrades() {
    let initial = account(8, 2, 1);
    let mut target = initial.clone();
    let (mut store, genesis, config) = fixture(&initial).await;
    let assets: Vec<_> = initial.vault().assets().collect();
    let changed_code = account(8, 2, 2).code().clone();
    let patch = AccountPatch::new(
        initial.id(),
        AccountStoragePatch::from_entries([
            (
                StorageSlotName::mock(0),
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([
                        (key(0), Word::empty()),
                        (key(1), word(99)),
                        (key(12), word(13)),
                    ])),
                }),
            ),
            (
                StorageSlotName::mock(7),
                StorageSlotPatch::Value(StorageValuePatch::Create { value: word(7) }),
            ),
        ])
        .unwrap(),
        AccountVaultPatch::new(BTreeMap::from([(assets[0].id(), Word::empty())])).unwrap(),
        AccountCodePatch::new(Some(changed_code.clone())),
        Some(Felt::new_unchecked(2)),
    )
    .unwrap();
    apply(&mut store, &genesis, &config, &mut target, patch).await;
    let rpc = service_with_config(
        &store,
        crate::SyncAccountConfig {
            limit: std::num::NonZeroU32::new(12).unwrap(),
            snapshot_threshold: 0,
            ..Default::default()
        },
    );
    let response = rpc
        .sync_account(request(&initial, Some(0), 1, Some(initial.code().commitment())))
        .await
        .unwrap()
        .into_inner();
    assert!(!payload(&response).1);
    assert!(response.code.is_some());
    assert_eq!(reconstruct(response, Some(&initial), initial.code()), target);
    let cached = rpc
        .sync_account(request(&target, Some(0), 1, Some(changed_code.commitment())))
        .await
        .unwrap()
        .into_inner();
    assert!(cached.code.is_none());
    assert_eq!(reconstruct(cached, Some(&initial), &changed_code), target);
    let historical = rpc
        .sync_account(request(&initial, None, 0, Some(Word::empty())))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reconstruct(historical, None, initial.code()), initial);

    let previous = target.clone();
    let patch = AccountPatch::new(
        target.id(),
        AccountStoragePatch::from_entries([(
            StorageSlotName::mock(0),
            StorageSlotPatch::Map(StorageMapPatch::Remove),
        )])
        .unwrap(),
        AccountVaultPatch::default(),
        AccountCodePatch::default(),
        Some(Felt::new_unchecked(3)),
    )
    .unwrap();
    apply(&mut store, &genesis, &config, &mut target, patch).await;
    let response = service_with_config(
        &store,
        crate::SyncAccountConfig {
            limit: std::num::NonZeroU32::new(2).unwrap(),
            snapshot_threshold: 0,
            ..Default::default()
        },
    )
    .sync_account(request(&target, Some(1), 2, Some(changed_code.commitment())))
    .await
    .unwrap()
    .into_inner();
    assert!(!payload(&response).1);
    assert_eq!(reconstruct(response, Some(&previous), &changed_code), target);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_tuning_selects_snapshots_and_caps_combined_deltas() {
    let initial = account(8, 2, 1);
    let mut target = initial.clone();
    let (mut store, genesis, config) = fixture(&initial).await;
    let asset = initial.vault().assets().next().unwrap();
    let patch = AccountPatch::new(
        initial.id(),
        AccountStoragePatch::from_entries([
            (
                StorageSlotName::mock(0),
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([(key(0), word(99))])),
                }),
            ),
            (
                StorageSlotName::mock(1),
                StorageSlotPatch::Map(StorageMapPatch::Create {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([(key(0), word(88))])),
                }),
            ),
        ])
        .unwrap(),
        AccountVaultPatch::new(BTreeMap::from([(asset.id(), Word::empty())])).unwrap(),
        AccountCodePatch::default(),
        Some(Felt::new_unchecked(2)),
    )
    .unwrap();
    apply(&mut store, &genesis, &config, &mut target, patch).await;
    // The target has ten entries; its delta has two map entries and one asset deletion.
    for (threshold, cap, snapshot) in [(10, 3, true), (9, 3, false), (0, 2, true), (0, 1, true)] {
        let rpc = service_with_config(
            &store,
            crate::SyncAccountConfig {
                snapshot_threshold: threshold,
                delta_limit: std::num::NonZeroU32::new(cap).unwrap(),
                ..Default::default()
            },
        );
        let response = rpc
            .sync_account(request(&initial, Some(0), 1, None))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(payload(&response).1, snapshot);
        assert_eq!(reconstruct(response, Some(&initial), initial.code()), target);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_delta_pages_share_the_entry_budget() {
    for (map_changes, vault_changes) in [(0, 2), (2, 0), (2, 1), (2, 2)] {
        let initial = account(2, 2, 1);
        let mut target = initial.clone();
        let (mut store, genesis, config) = fixture(&initial).await;
        let patch = AccountPatch::new(
            initial.id(),
            AccountStoragePatch::from_entries([(
                StorageSlotName::mock(0),
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_raw(
                        (0..map_changes).map(|n| (key(n), word(n + 99))).collect(),
                    ),
                }),
            )])
            .unwrap(),
            AccountVaultPatch::new(
                initial
                    .vault()
                    .assets()
                    .take(vault_changes)
                    .map(|asset| (asset.id(), Word::empty()))
                    .collect(),
            )
            .unwrap(),
            AccountCodePatch::default(),
            Some(Felt::new_unchecked(2)),
        )
        .unwrap();
        apply(&mut store, &genesis, &config, &mut target, patch).await;

        for cap in 1..=4 {
            let rpc = service_with_config(
                &store,
                crate::SyncAccountConfig {
                    snapshot_threshold: 0,
                    delta_limit: std::num::NonZeroU32::new(cap).unwrap(),
                    ..Default::default()
                },
            );
            let response = rpc
                .sync_account(request(&initial, Some(0), 1, None))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                payload(&response).1,
                map_changes as usize + vault_changes > cap as usize,
                "maps={map_changes}, vault={vault_changes}, cap={cap}"
            );
            assert_eq!(reconstruct(response, Some(&initial), initial.code()), target);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_delta_clears_keys_from_recreated_maps() {
    let initial = account(3, 0, 1);
    let mut target = initial.clone();
    let (mut store, genesis, config) = fixture(&initial).await;
    let mut states = Vec::new();
    for (nonce, map) in [
        (2, StorageMapPatch::Remove),
        (
            3,
            StorageMapPatch::Create {
                entries: StorageMapPatchEntries::from_raw(BTreeMap::from([
                    (key(1), word(2)),
                    (key(100), word(100)),
                    (key(101), word(101)),
                    (key(102), word(102)),
                ])),
            },
        ),
    ] {
        let patch = AccountPatch::new(
            initial.id(),
            AccountStoragePatch::from_entries([(
                StorageSlotName::mock(0),
                StorageSlotPatch::Map(map),
            )])
            .unwrap(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::new_unchecked(nonce)),
        )
        .unwrap();
        apply(&mut store, &genesis, &config, &mut target, patch).await;
        states.push(target.clone());
    }
    let rpc = service_with_config(
        &store,
        crate::SyncAccountConfig {
            snapshot_threshold: 0,
            ..Default::default()
        },
    );
    let response = rpc
        .sync_account(request(&initial, Some(0), 1, None))
        .await
        .unwrap()
        .into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(response, None, initial.code()), states[0]);

    // The larger cap exercises the shared streaming query's handling of recreated maps. This
    // requires the upstream fix: https://github.com/0xMiden/node/pull/2483#issuecomment-6468230960
    for (cap, snapshot) in [(3, true), (100, false)] {
        let rpc = service_with_config(
            &store,
            crate::SyncAccountConfig {
                snapshot_threshold: 0,
                delta_limit: std::num::NonZeroU32::new(cap).unwrap(),
                ..Default::default()
            },
        );
        let response = rpc
            .sync_account(request(&initial, Some(0), 2, None))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(payload(&response).1, snapshot);
        assert_eq!(reconstruct(response, Some(&initial), initial.code()), target);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_delta_handles_reverted_changes_and_preserves_historical_targets() {
    let initial = account(4, 2, 1);
    let mut target = initial.clone();
    let (mut store, genesis, config) = fixture(&initial).await;
    let asset = initial.vault().assets().next().unwrap();
    let mut states = Vec::new();
    for (nonce, existing, added, vault) in [
        (2, word(99), word(100), Word::empty()),
        (3, word(1), Word::empty(), asset.to_value_word()),
    ] {
        let patch = AccountPatch::new(
            initial.id(),
            AccountStoragePatch::from_entries([(
                StorageSlotName::mock(0),
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([
                        (key(0), existing),
                        (key(100), added),
                    ])),
                }),
            )])
            .unwrap(),
            AccountVaultPatch::new(BTreeMap::from([(asset.id(), vault)])).unwrap(),
            AccountCodePatch::default(),
            Some(Felt::new_unchecked(nonce)),
        )
        .unwrap();
        apply(&mut store, &genesis, &config, &mut target, patch).await;
        states.push(target.clone());
    }
    let rpc = service_with_config(
        &store,
        crate::SyncAccountConfig {
            snapshot_threshold: 0,
            ..Default::default()
        },
    );
    for (height, expected) in [(1, &states[0]), (2, &states[1])] {
        let response = rpc
            .sync_account(request(&initial, Some(0), height, None))
            .await
            .unwrap()
            .into_inner();
        assert!(!payload(&response).1);
        if height == 2 {
            assert_eq!(payload(&response).0.maps[0].entries.len(), 2);
            let vault = &payload(&response).0.vault;
            assert_eq!(vault.len(), 1);
            let value: Word = vault[0].value.clone().unwrap().decode_fields().unwrap();
            assert_eq!(value, asset.to_value_word());
        }
        assert_eq!(reconstruct(response, Some(&initial), initial.code()), *expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_size_limit_is_target_based_and_advertised() {
    let initial = account(8, 2, 1);
    let mut target = initial.clone();
    let (mut store, genesis, config) = fixture(&initial).await;
    let rpc = service(&store, 10);
    for from in [None, Some(0)] {
        for code in [None, Some(Word::empty())] {
            let error = rpc.sync_account(request(&initial, from, 0, code)).await.unwrap_err();
            assert_eq!(error.code(), tonic::Code::ResourceExhausted);
            assert_eq!(error.details(), &[5]);
        }
    }
    let limits = rpc
        .get_limits(Request::new(proto::miden::node::v1::GetLimitsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(limits.endpoints["SyncAccount"].parameters["account_entries"], 10);
    let patch = AccountPatch::new(
        initial.id(),
        AccountStoragePatch::from_entries([(
            StorageSlotName::mock(0),
            StorageSlotPatch::Map(StorageMapPatch::Update {
                entries: StorageMapPatchEntries::from_raw(
                    (1..8).map(|n| (key(n), Word::empty())).collect(),
                ),
            }),
        )])
        .unwrap(),
        AccountVaultPatch::default(),
        AccountCodePatch::default(),
        Some(Felt::new_unchecked(2)),
    )
    .unwrap();
    apply(&mut store, &genesis, &config, &mut target, patch).await;
    let response = service(&store, 4)
        .sync_account(request(&initial, Some(0), 1, None))
        .await
        .unwrap()
        .into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(response, None, initial.code()), target);
    let response = service(&store, 11)
        .sync_account(request(&initial, Some(0), 1, None))
        .await
        .unwrap()
        .into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(response, None, initial.code()), target);

    let small = target.clone();
    let patch = AccountPatch::new(
        target.id(),
        AccountStoragePatch::from_entries([(
            StorageSlotName::mock(0),
            StorageSlotPatch::Map(StorageMapPatch::Update {
                entries: StorageMapPatchEntries::from_raw(
                    (1..8).map(|n| (key(n), word(n + 1))).collect(),
                ),
            }),
        )])
        .unwrap(),
        AccountVaultPatch::default(),
        AccountCodePatch::default(),
        Some(Felt::new_unchecked(3)),
    )
    .unwrap();
    apply(&mut store, &genesis, &config, &mut target, patch).await;
    let error = rpc.sync_account(request(&target, Some(1), 2, None)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    let response = service(&store, 4)
        .sync_account(request(&small, None, 1, None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reconstruct(response, None, initial.code()), small);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_validates_targets_and_bootstraps_after_starting_state_pruning() {
    let account = account(1, 0, 1);
    let (mut store, _, config) = fixture(&account).await;
    let rpc = service(&store, 2);
    for (from, target, code) in [(Some(2), 1, 2), (Some(1), 1, 3)] {
        let error = rpc.sync_account(request(&account, from, target, None)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(error.details(), &[code]);
    }
    for _ in 0..52 {
        let block = next_block_with_protocol_config(&store, &config).await;
        store.writer.apply_block(block, None).await.unwrap();
    }
    let response = rpc
        .sync_account(request(&account, Some(0), 52, None))
        .await
        .unwrap()
        .into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(response, None, account.code()), account);
    let error = rpc.sync_account(request(&account, None, 0, None)).await.unwrap_err();
    assert_eq!(error.details(), &[4]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_rejects_malformed_private_and_unknown_accounts() {
    let account = account(1, 0, 1);
    let (store, ..) = fixture(&account).await;
    let rpc = service(&store, 2);
    let mut missing = request(&account, None, 0, None).into_inner();
    missing.range.as_mut().unwrap().to_block_inclusive = None;
    let error = rpc.sync_account(Request::new(missing)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.details(), &[2]);
    let mut private = request(&account, None, 0, None).into_inner();
    let id: AccountId = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    private.account_id = Some(id.into());
    let error = rpc.sync_account(Request::new(private)).await.unwrap_err();
    assert_eq!(error.details(), &[6]);
    let mut unknown = request(&account, None, 0, None).into_inner();
    let id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    unknown.account_id = Some(id.into());
    let error = rpc.sync_account(Request::new(unknown)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    assert_eq!(error.details(), &[7]);
    let mut malformed = request(&account, None, 0, None).into_inner();
    malformed.account_id = None;
    let error = rpc.sync_account(Request::new(malformed)).await.unwrap_err();
    assert_eq!(error.details(), &[1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_accepts_and_advertises_large_configured_limits() {
    let account = account(1, 0, 1);
    let (store, ..) = fixture(&account).await;
    for limit in [40_001, u32::MAX] {
        let rpc = service(&store, limit);
        let response =
            rpc.sync_account(request(&account, None, 0, None)).await.unwrap().into_inner();
        assert_eq!(reconstruct(response, None, account.code()), account);
        let limits = rpc
            .get_limits(Request::new(proto::miden::node::v1::GetLimitsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(limits.endpoints["SyncAccount"].parameters["account_entries"], limit);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_read_transaction_survives_updates_and_history_pruning() {
    let initial = account(1, 0, 1);
    let mut target = initial.clone();
    let (mut store, genesis, config) = fixture(&initial).await;
    let id = initial.id();
    let commitment = initial.code().commitment();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let state = Arc::clone(&store.state);
    let read = tokio::spawn(async move {
        state
            .with_view(async |view| {
                view.read(0.into()..=0.into(), move |tx, blocks| {
                    let block = blocks.scoped_end();
                    let size = miden_node_store::queries::account_size(tx, id, block)?;
                    started_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    let snapshot = miden_node_store::queries::account_state(tx, id, block)?;
                    let code = miden_node_store::queries::account_code(tx, commitment)?.unwrap();
                    Ok::<_, miden_node_store::DatabaseError>((size, snapshot, code))
                })
                .await
                .unwrap()
            })
            .await
    });
    started_rx.await.unwrap();
    let replacement = account(1, 0, 2).code().clone();
    let patch = AccountPatch::new(
        id,
        AccountStoragePatch::from_entries([(
            StorageSlotName::mock(0),
            StorageSlotPatch::Map(StorageMapPatch::Update {
                entries: StorageMapPatchEntries::from_raw(BTreeMap::from([(key(0), word(99))])),
            }),
        )])
        .unwrap(),
        AccountVaultPatch::default(),
        AccountCodePatch::new(Some(replacement)),
        Some(Felt::new_unchecked(2)),
    )
    .unwrap();
    apply(&mut store, &genesis, &config, &mut target, patch).await;
    for _ in 1..52 {
        let block = next_block_with_protocol_config(&store, &config).await;
        store.writer.apply_block(block, None).await.unwrap();
    }
    resume_tx.send(()).unwrap();
    let (size, snapshot, code) = read.await.unwrap().unwrap();
    assert_eq!(size.storage_map_entries, 1);
    assert_eq!(snapshot.header.to_commitment(), initial.to_commitment());
    assert_eq!(snapshot.maps[&StorageSlotName::mock(0)], BTreeMap::from([(key(0), word(1))]));
    assert_eq!(code, *initial.code());
    let block = next_block_with_protocol_config(&store, &config).await;
    store.writer.apply_block(block, None).await.unwrap();
    let current = store
        .state
        .view()
        .read(0.into()..=0.into(), move |tx, blocks| {
            (
                miden_node_store::queries::account_size(tx, id, blocks.scoped_end()),
                miden_node_store::queries::account_code(tx, commitment),
            )
        })
        .await
        .unwrap();
    assert!(matches!(current.0, Err(miden_node_store::DatabaseError::BlockPruned { .. })));
    assert!(current.1.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_read_transactions_validate_the_requested_block_range() {
    let account = account(1, 0, 1);
    let (store, ..) = fixture(&account).await;
    let id = account.id();
    let future = store
        .state
        .view()
        .read(1.into()..=1.into(), move |tx, blocks| {
            miden_node_store::queries::account_size(tx, id, blocks.scoped_end())
        })
        .await;
    assert!(matches!(future, Err(miden_node_store::DatabaseError::RangeBeyondTip(_))));
    let reversed = store.state.view().read(1.into()..=0.into(), |_, _| ()).await;
    assert!(matches!(
        reversed,
        Err(miden_node_store::DatabaseError::InvalidBlockRange { .. })
    ));
    let size = store
        .state
        .view()
        .read(0.into()..=0.into(), move |tx, blocks| {
            miden_node_store::queries::account_size(tx, id, blocks.scoped_start())
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(size.storage_map_entries, 1);
}
