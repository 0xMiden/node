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
use miden_protocol::block::account_tree::{AccountIdKey, AccountTree};
use miden_protocol::block::{BlockAccountUpdate, BlockBody, BlockHeader};
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_standards::code_builder::CodeBuilder;
use v2::node_service_server::NodeService as V2Api;
use v2::sync_account_response::Update;
use v2::{AccountContents, SyncAccountRequest, SyncAccountResponse};

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
    RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::full_node(source_rpc_client(), None),
        None,
        NonZeroUsize::MIN,
        None,
        config,
    )
}

fn request(account: &Account, from: Option<u32>, target: u32) -> Request<SyncAccountRequest> {
    Request::new(SyncAccountRequest {
        account_id: Some(account.id().into()),
        range: Some(v2::StateDeltaRange {
            from_block_exclusive: from,
            to_block_inclusive: Some(target),
        }),
    })
}

fn payload(response: &SyncAccountResponse) -> (&AccountContents, bool) {
    match response.update.as_ref().unwrap() {
        Update::Snapshot(state) => (state, true),
        Update::Delta(state) => (state, false),
    }
}

/// Reconstructs state from the public response, retaining cached contents only for deltas.
async fn reconstruct(
    store: &TestStore,
    id: AccountId,
    response: SyncAccountResponse,
    starting_state: Option<&Account>,
    cached: &AccountCode,
) -> Account {
    let (state, full) = payload(&response);
    let rpc = service(store, 1000);
    let block_num = Some(response.block_num);
    let (header, storage_header) = account_headers_at(&rpc, id, block_num).await;
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
        let key = entry.asset_id.unwrap().decode_fields().unwrap().verify().unwrap();
        if let Some(value) = entry.asset.clone() {
            let asset = value.decode_fields().unwrap().verify().unwrap();
            assert_eq!(asset.id(), key);
            vault.insert(key, asset.to_value_word());
        } else {
            assert!(!full);
            vault.remove(&key);
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
    let code = cached.clone();
    let account = Account::new(
        header.id(),
        AssetVault::new(&assets).unwrap(),
        storage,
        code,
        header.nonce(),
        None,
    )
    .unwrap();
    let tree = rpc
        .get_account_witnesses(Request::new(v2::GetAccountWitnessesRequest {
            account_ids: vec![id.into()],
            block_num,
        }))
        .await
        .unwrap()
        .into_inner()
        .account_tree
        .unwrap()
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap();
    let reference = store
        .state
        .view()
        .get_block_header(Some(response.block_num.into()), false)
        .await
        .unwrap()
        .0
        .unwrap();
    assert_eq!(tree.root(), reference.account_root());
    assert_eq!(
        account.to_commitment(),
        tree.get_value(&AccountIdKey::from(id).as_word()).unwrap()
    );
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
    let body =
        BlockBody::new(vec![update], vec![], vec![], vec![], PublicTransactionLogs::default())
            .unwrap();
    let base = next_block_with_protocol_config(store, config).await;
    let h = base.header();
    let header = BlockHeader::new(
        h.prev_block_commitment(),
        h.block_num(),
        h.chain_commitment(),
        root,
        h.nullifier_root(),
        h.code_tree_root(),
        body.compute_block_note_tree().root(),
        body.compute_transactions_commitment(),
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
async fn v2_contents_only_snapshot_authenticates_contents() {
    let account = account(8, 2, 1);
    let (store, ..) = fixture(&account).await;
    let rpc = service(&store, 11);
    let response = rpc.sync_account(request(&account, None, 0)).await.unwrap().into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(&store, account.id(), response, None, account.code()).await, account);
    let response = rpc.sync_account(request(&account, Some(0), 0)).await.unwrap().into_inner();
    assert!(!payload(&response).1);
    assert_eq!(payload(&response).0.maps, []);
    assert_eq!(payload(&response).0.vault, []);
    assert_eq!(
        reconstruct(&store, account.id(), response, Some(&account), account.code()).await,
        account
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_snapshot_preserves_empty_map_slots() {
    let account = account(0, 0, 1);
    let (store, ..) = fixture(&account).await;
    let rpc = service(&store, 1_000);
    let response = rpc.sync_account(request(&account, None, 0)).await.unwrap().into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(&store, account.id(), response, None, account.code()).await, account);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_contents_only_unchanged_account_returns_empty_delta() {
    let account = account(8, 2, 1);
    let (mut store, _, config) = fixture(&account).await;
    let block = next_block_with_protocol_config(&store, &config).await;
    store.writer.apply_block(block, None).await.unwrap();
    let rpc = service(&store, 11);
    let response = rpc.sync_account(request(&account, Some(0), 1)).await.unwrap().into_inner();
    assert_eq!(response.block_num, 1);
    assert!(!payload(&response).1);
    assert_eq!(payload(&response).0.maps, []);
    assert_eq!(payload(&response).0.vault, []);
    assert_eq!(
        reconstruct(&store, account.id(), response, Some(&account), account.code()).await,
        account
    );

    let error = service(&store, 10)
        .sync_account(request(&account, Some(0), 1))
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
    let response = rpc.sync_account(request(&initial, Some(0), 1)).await.unwrap().into_inner();
    assert!(!payload(&response).1);
    assert_eq!(
        reconstruct(&store, target.id(), response, Some(&initial), &changed_code).await,
        target
    );
    let historical = rpc.sync_account(request(&initial, None, 0)).await.unwrap().into_inner();
    assert_eq!(
        reconstruct(&store, initial.id(), historical, None, initial.code()).await,
        initial
    );

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
    .sync_account(request(&target, Some(1), 2))
    .await
    .unwrap()
    .into_inner();
    assert!(!payload(&response).1);
    assert_eq!(
        reconstruct(&store, target.id(), response, Some(&previous), &changed_code).await,
        target
    );
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
        let response = rpc.sync_account(request(&initial, Some(0), 1)).await.unwrap().into_inner();
        assert_eq!(payload(&response).1, snapshot);
        assert_eq!(
            reconstruct(&store, target.id(), response, Some(&initial), initial.code()).await,
            target
        );
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
            let response =
                rpc.sync_account(request(&initial, Some(0), 1)).await.unwrap().into_inner();
            assert_eq!(
                payload(&response).1,
                map_changes as usize + vault_changes > cap as usize,
                "maps={map_changes}, vault={vault_changes}, cap={cap}"
            );
            assert_eq!(
                reconstruct(&store, target.id(), response, Some(&initial), initial.code()).await,
                target
            );
        }
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
        let response =
            rpc.sync_account(request(&initial, Some(0), height)).await.unwrap().into_inner();
        assert!(!payload(&response).1);
        if height == 2 {
            assert_eq!(payload(&response).0.maps[0].entries.len(), 2);
            let vault = &payload(&response).0.vault;
            assert_eq!(vault.len(), 1);
            let actual = vault[0].asset.clone().unwrap().decode_fields().unwrap().verify().unwrap();
            assert_eq!(actual, asset);
        }
        assert_eq!(
            reconstruct(&store, expected.id(), response, Some(&initial), initial.code()).await,
            *expected
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_size_limit_is_target_based_and_advertised() {
    let initial = account(8, 2, 1);
    let mut target = initial.clone();
    let (mut store, genesis, config) = fixture(&initial).await;
    let rpc = service(&store, 10);
    for from in [None, Some(0)] {
        let error = rpc.sync_account(request(&initial, from, 0)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(error.details(), &[5]);
    }
    let limits = V2Api::get_limits(&rpc, Request::new(v2::GetLimitsRequest {}))
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
        .sync_account(request(&initial, Some(0), 1))
        .await
        .unwrap()
        .into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(&store, target.id(), response, None, initial.code()).await, target);
    let response = service(&store, 11)
        .sync_account(request(&initial, Some(0), 1))
        .await
        .unwrap()
        .into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(&store, target.id(), response, None, initial.code()).await, target);

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
    let error = rpc.sync_account(request(&target, Some(1), 2)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    let response = service(&store, 4)
        .sync_account(request(&small, None, 1))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reconstruct(&store, small.id(), response, None, initial.code()).await, small);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_validates_targets_and_bootstraps_after_starting_state_pruning() {
    let account = account(1, 0, 1);
    let (mut store, _, config) = fixture(&account).await;
    let rpc = service(&store, 2);
    for (from, target, code) in [(Some(2), 1, 2), (Some(1), 1, 3)] {
        let error = rpc.sync_account(request(&account, from, target)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(error.details(), &[code]);
    }
    for _ in 0..52 {
        let block = next_block_with_protocol_config(&store, &config).await;
        store.writer.apply_block(block, None).await.unwrap();
    }
    let response = rpc.sync_account(request(&account, Some(0), 52)).await.unwrap().into_inner();
    assert!(payload(&response).1);
    assert_eq!(reconstruct(&store, account.id(), response, None, account.code()).await, account);
    let error = rpc.sync_account(request(&account, None, 0)).await.unwrap_err();
    assert_eq!(error.details(), &[4]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_rejects_malformed_private_and_unknown_accounts() {
    let account = account(1, 0, 1);
    let (store, ..) = fixture(&account).await;
    let rpc = service(&store, 2);
    let mut missing = request(&account, None, 0).into_inner();
    missing.range.as_mut().unwrap().to_block_inclusive = None;
    let error = rpc.sync_account(Request::new(missing)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.details(), &[2]);
    let mut private = request(&account, None, 0).into_inner();
    let id: AccountId = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    private.account_id = Some(id.into());
    let error = rpc.sync_account(Request::new(private)).await.unwrap_err();
    assert_eq!(error.details(), &[6]);
    let mut unknown = request(&account, None, 0).into_inner();
    let id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    unknown.account_id = Some(id.into());
    let error = rpc.sync_account(Request::new(unknown)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    assert_eq!(error.details(), &[7]);
    let mut malformed = request(&account, None, 0).into_inner();
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
        let response = rpc.sync_account(request(&account, None, 0)).await.unwrap().into_inner();
        assert_eq!(
            reconstruct(&store, account.id(), response, None, account.code()).await,
            account
        );
        let limits = V2Api::get_limits(&rpc, Request::new(v2::GetLimitsRequest {}))
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
            .read(move |view| {
                let blocks = view.snapshot.scope_range(0.into()..=0.into())?;
                let block = blocks.scoped_end();
                let size = view.tx.account_size(id, block)?;
                started_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                let snapshot = view.tx.account_state(id, block)?;
                let code = view.tx.account_code(commitment)?.unwrap();
                Ok::<_, miden_node_store::DatabaseError>((size, snapshot, code))
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

    // Recent snapshots can delay pruning. Keep the original transaction open until a fresh
    // transaction observes that the superseded code has been deleted.
    let current_size = loop {
        let block = next_block_with_protocol_config(&store, &config).await;
        store.writer.apply_block(block, None).await.unwrap();
        let (size, code) = store
            .state
            .read(move |view| {
                let blocks = view.snapshot.scope_range(0.into()..=0.into())?;
                Ok::<_, miden_node_store::DatabaseError>((
                    view.tx.account_size(id, blocks.scoped_end()),
                    view.tx.account_code(commitment),
                ))
            })
            .await
            .unwrap();
        if code.unwrap().is_none() {
            break size;
        }
        assert!(store.state.committed_tip().as_u32() < 128, "superseded code was never pruned");
    };
    assert!(matches!(current_size, Err(miden_node_store::DatabaseError::BlockPruned { .. })));

    resume_tx.send(()).unwrap();
    let (size, snapshot, code) = read.await.unwrap().unwrap();
    assert_eq!(size.storage_map_entries, 1);
    assert_eq!(snapshot.header.to_commitment(), initial.to_commitment());
    assert_eq!(snapshot.maps[&StorageSlotName::mock(0)], BTreeMap::from([(key(0), word(1))]));
    assert_eq!(code, *initial.code());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_read_transactions_validate_the_requested_block_range() {
    let account = account(1, 0, 1);
    let (store, ..) = fixture(&account).await;
    let id = account.id();
    let future = store
        .state
        .read(move |view| {
            let blocks = view.snapshot.scope_range(1.into()..=1.into())?;
            view.tx.account_size(id, blocks.scoped_end())
        })
        .await;
    assert!(matches!(future, Err(miden_node_store::DatabaseError::RangeBeyondTip(_))));
    let reversed = store.state.read(|view| view.snapshot.scope_range(1.into()..=0.into())).await;
    assert!(matches!(
        reversed,
        Err(miden_node_store::DatabaseError::InvalidBlockRange { .. })
    ));
    let size = store
        .state
        .read(move |view| {
            let blocks = view.snapshot.scope_range(0.into()..=0.into())?;
            view.tx.account_size(id, blocks.scoped_start())
        })
        .await
        .unwrap();
    assert_eq!(size.storage_map_entries, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_account_infos() {
    use v2::get_account_infos_request::AccountQuery;
    use v2::get_account_infos_response::account_info::Result as Info;
    let initial = account(1, 0, 1);
    let (mut store, _, config) = fixture(&initial).await;
    let block = next_block_with_protocol_config(&store, &config).await;
    store.writer.apply_block(block, None).await.unwrap();
    let rpc = service(&store, 100);
    let query = |id: AccountId, known: Option<Word>| AccountQuery {
        account_id: Some(id.into()),
        known_commitment: known.map(Into::into),
    };
    let existing = query(initial.id(), None);
    let absent = query(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap(), None);
    let call = |height, accounts| {
        rpc.get_account_infos(Request::new(v2::GetAccountInfosRequest {
            block_num: height,
            accounts,
        }))
    };
    for known in [None, Some(Word::empty()), Some(initial.to_commitment())] {
        let response = call(Some(0), vec![absent.clone(), query(initial.id(), known)])
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.block_num, 0);
        assert!(matches!(response.accounts[0].result, Some(Info::NotFound(()))));
        match response.accounts[1].result.as_ref().unwrap() {
            Info::Unchanged(()) => assert_eq!(known, Some(initial.to_commitment())),
            Info::Headers(headers) => {
                assert_ne!(known, Some(initial.to_commitment()));
                assert_eq!(headers.account_header, Some(AccountHeader::from(&initial).into()));
            },
            Info::NotFound(()) => panic!("genesis account should exist"),
        }
    }
    for (height, accounts) in [
        (None, vec![existing.clone()]),
        (Some(0), vec![existing.clone(), existing.clone()]),
        (
            Some(0),
            vec![existing, query(AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap(), None)],
        ),
    ] {
        assert_eq!(call(height, accounts).await.unwrap_err().code(), tonic::Code::InvalidArgument);
    }
    assert!(call(Some(2), vec![absent]).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_account_witnesses() {
    use miden_protocol::block::account_tree::AccountIdKey;
    let initial = account(1, 0, 1);
    let id = initial.id();
    let same_prefix =
        AccountId::try_from_elements(id.suffix() + Felt::from(256u32), id.prefix().as_felt())
            .unwrap();
    let private = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
    let mut builder = MockChainBuilder::new();
    builder.add_account(initial.clone()).unwrap();
    let mut other = builder.add_existing_wallet(Auth::IncrNonce).unwrap();
    let chain = builder.build().unwrap();
    let genesis = chain.latest_block();
    let config = chain.protocol_config().clone();
    let mut store = TestStore::start_from_mock_genesis(&genesis, &config).await;
    let patch = AccountPatch::new(
        other.id(),
        AccountStoragePatch::default(),
        AccountVaultPatch::default(),
        AccountCodePatch::default(),
        Some(other.nonce() + Felt::ONE),
    )
    .unwrap();
    apply(&mut store, &genesis, &config, &mut other, patch).await;
    let latest = store.state.view().get_block_header(None, false).await.unwrap().0.unwrap();
    assert_ne!(genesis.header().account_root(), latest.account_root());
    let rpc = service(&store, 100);
    let call = |height, ids: Vec<AccountId>| {
        rpc.get_account_witnesses(Request::new(v2::GetAccountWitnessesRequest {
            account_ids: ids.into_iter().map(Into::into).collect(),
            block_num: height,
        }))
    };
    for (height, root) in [(0, genesis.header().account_root()), (1, latest.account_root())] {
        let response =
            call(Some(height), vec![same_prefix, private, id]).await.unwrap().into_inner();
        assert_eq!(response.block_num, height);
        let tree = response.account_tree.unwrap().decode_fields().unwrap().verify().unwrap();
        assert_eq!(tree.root(), root);
        assert_eq!(
            tree.get_value(&AccountIdKey::from(id).as_word()).unwrap(),
            initial.to_commitment()
        );
        for absent in [private, same_prefix] {
            assert_eq!(
                tree.get_value(&AccountIdKey::from(absent).as_word()).unwrap(),
                Word::empty()
            );
        }
    }
    for (height, ids) in [
        (None, vec![id]),
        (Some(0), vec![]),
        (Some(0), vec![id, id]),
        (Some(2), vec![id]),
        (Some(0), vec![id; 1001]),
    ] {
        assert!(call(height, ids).await.is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_entry_witnesses() {
    use miden_protocol::account::{StorageMapPatch, StorageMapPatchEntries, StorageSlotPatch};
    for count in [1, 65] {
        let (account, empty_map, value_slot) = entry_witness_account(count);
        let (mut store, genesis, config) = fixture(&account).await;
        let asset = account.vault().assets().next().unwrap();
        let mut updated = account.clone();
        let patch = AccountPatch::new(
            account.id(),
            AccountStoragePatch::from_entries([(
                StorageSlotName::mock(0),
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([(key(0), word(99))])),
                }),
            )])
            .unwrap(),
            AccountVaultPatch::new(BTreeMap::from([(asset.id(), Word::empty())])).unwrap(),
            AccountCodePatch::default(),
            Some(account.nonce() + Felt::ONE),
        )
        .unwrap();
        apply(&mut store, &genesis, &config, &mut updated, patch).await;
        assert_ne!(updated.to_header().vault_root(), account.to_header().vault_root());
        let rpc = service(&store, 100);
        let ids = vault_stream_values(count + 1);
        let vault = |assets: Vec<AssetId>| {
            rpc.get_account_vault_witnesses(Request::new(v2::GetAccountVaultWitnessesRequest {
                account_id: Some(account.id().into()),
                block_num: Some(0),
                asset_ids: assets.into_iter().map(Into::into).collect(),
            }))
        };
        let present = ids[0].0;
        let absent = ids.last().unwrap().0;
        let empty = vault(vec![]).await.unwrap().into_inner();
        let empty_proof = empty.vault.unwrap().decode_fields().unwrap().verify().unwrap();
        assert_eq!(empty_proof.root(), account.to_header().vault_root());
        let response = vault(vec![present, absent]).await.unwrap().into_inner();
        let proof = response.vault.unwrap().decode_fields().unwrap().verify().unwrap();
        assert_eq!(proof.root(), account.to_header().vault_root());
        assert_eq!(
            proof.get_value(&present.hash().as_word()).unwrap(),
            ids[0].1.as_ref().unwrap().to_value_word()
        );
        assert_eq!(proof.get_value(&absent.hash().as_word()).unwrap(), Word::empty());
        assert!(
            vault(vault_stream_values(64).into_iter().map(|(id, _)| id).collect())
                .await
                .is_ok()
        );
        assert!(vault(vec![present; 65]).await.is_err());
        let map = StorageSlotName::mock(0);
        let query = |name: &StorageSlotName, keys: Vec<StorageMapKey>| {
            v2::get_account_storage_witnesses_request::MapQuery {
                slot_name: name.to_string(),
                keys: keys.into_iter().map(|key| Word::from(key).into()).collect(),
            }
        };
        let maps = |maps| {
            rpc.get_account_storage_witnesses(Request::new(v2::GetAccountStorageWitnessesRequest {
                account_id: Some(account.id().into()),
                block_num: Some(0),
                maps,
            }))
        };
        let response =
            maps(vec![query(&map, (0..63).map(key).collect()), query(&empty_map, vec![key(3)])])
                .await
                .unwrap()
                .into_inner();
        assert_eq!(response.maps[0].slot_name, map.to_string());
        assert_eq!(response.maps[1].slot_name, empty_map.to_string());
        let empty =
            response.maps[1].map.clone().unwrap().decode_fields().unwrap().verify().unwrap();
        assert_eq!(empty.get_value(&key(3).hash().into()).unwrap(), Word::empty());
        let proof = response
            .maps
            .into_iter()
            .next()
            .unwrap()
            .map
            .unwrap()
            .decode_fields()
            .unwrap()
            .verify()
            .unwrap();
        assert_eq!(
            proof.root(),
            account.storage().to_header().find_slot_header_by_name(&map).unwrap().value()
        );
        assert_eq!(proof.get_value(&key(0).hash().into()).unwrap(), word(1));
        assert_eq!(proof.get_value(&key(3).hash().into()).unwrap(), Word::empty());
        for queries in [
            vec![query(&map, vec![key(0); 64]), query(&empty_map, vec![key(1)])],
            vec![query(&value_slot, vec![])],
            vec![query(&map, vec![]), query(&map, vec![])],
            vec![query(&StorageSlotName::mock(31), vec![key(0)])],
        ] {
            assert!(maps(queries).await.is_err());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_account_sync_at_reference_block() {
    use tokio_stream::StreamExt;

    let tracked = account(2, 1, 1);
    let (mut store, _, config) = fixture(&tracked).await;
    let commitment = tracked.to_commitment();
    let (reference, tx) = commit_pass_through(&mut store, &config, &tracked).await;
    let rpc = service(&store, 100);
    let tip = next_block_with_protocol_config(&store, &config).await;
    store.writer.apply_block(tip, None).await.unwrap();
    let anchor = V2Api::sync_chain_mmr(
        &rpc,
        Request::new(v2::SyncChainMmrRequest {
            current_client_block_height: 0,
            finality_level: v2::FinalityLevel::Committed as i32,
            target_block_num: Some(1),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(anchor.block_header, Some(reference.into()));
    let results = rpc
        .get_account_infos(Request::new(v2::GetAccountInfosRequest {
            block_num: Some(1),
            accounts: vec![v2::get_account_infos_request::AccountQuery {
                account_id: Some(tracked.id().into()),
                known_commitment: Some(commitment.into()),
            }],
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        results.accounts[0].result,
        Some(v2::get_account_infos_response::account_info::Result::Unchanged(()))
    ));
    let response = rpc.sync_account(request(&tracked, Some(0), 1)).await.unwrap().into_inner();
    assert_eq!(
        reconstruct(&store, tracked.id(), response, Some(&tracked), tracked.code()).await,
        tracked
    );
    let mut activity = V2Api::sync_transactions(
        &rpc,
        Request::new(v2::SyncTransactionsRequest {
            account_ids: vec![tracked.id().into()],
            range: Some(v2::StateDeltaRange {
                from_block_exclusive: Some(0),
                to_block_inclusive: Some(1),
            }),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(
        activity.next().await.unwrap().unwrap().transaction.unwrap().header,
        Some((&tx).into())
    );
    assert!(activity.next().await.is_none());
}

async fn account_headers_at(
    rpc: &RpcService,
    id: AccountId,
    block_num: Option<u32>,
) -> (AccountHeader, AccountStorageHeader) {
    let account_id = Some(id.into());
    let info = rpc
        .get_account_infos(Request::new(v2::GetAccountInfosRequest {
            block_num,
            accounts: vec![v2::get_account_infos_request::AccountQuery {
                account_id,
                known_commitment: None,
            }],
        }))
        .await
        .unwrap()
        .into_inner()
        .accounts
        .pop()
        .unwrap();
    let Some(v2::get_account_infos_response::account_info::Result::Headers(headers)) = info.result
    else {
        panic!("account headers required");
    };
    let header: AccountHeader =
        headers.account_header.unwrap().decode_fields().unwrap().verify().unwrap();
    let storage_header: AccountStorageHeader =
        headers.storage_header.unwrap().decode_fields().unwrap().verify().unwrap();
    assert_eq!(storage_header.to_commitment(), header.storage_commitment());
    (header, storage_header)
}

fn entry_witness_account(count: u32) -> (Account, StorageSlotName, StorageSlotName) {
    let base = account(2, count, 1);
    let empty_map = StorageSlotName::mock(1);
    let value_slot = StorageSlotName::mock(2);
    let slots = base
        .storage()
        .slots()
        .iter()
        .cloned()
        .chain([
            StorageSlot::with_map(empty_map.clone(), StorageMap::default()),
            StorageSlot::with_value(value_slot.clone(), word(5)),
        ])
        .collect();
    let account = Account::new(
        base.id(),
        base.vault().clone(),
        AccountStorage::new(slots).unwrap(),
        base.code().clone(),
        base.nonce(),
        None,
    )
    .unwrap();
    (account, empty_map, value_slot)
}

async fn commit_pass_through(
    store: &mut TestStore,
    config: &ProtocolConfig,
    tracked: &Account,
) -> (BlockHeader, TransactionHeader) {
    use miden_protocol::transaction::OrderedTransactionHeaders;
    let commitment = tracked.to_commitment();
    let logs = TransactionLogs::default();
    let tx = TransactionHeader::new(
        tracked.id(),
        commitment,
        commitment,
        InputNotes::default(),
        vec![],
        logs.commitment(),
        CodePatch::default().commitment(),
    )
    .unwrap();
    let public_logs =
        PublicTransactionLogs::new([(tx.id(), logs)].into(), [&tx].into_iter()).unwrap();
    let body = BlockBody::new(
        vec![],
        vec![],
        vec![],
        vec![OrderedTransactionHeaders::new_unchecked(vec![tx.clone()])],
        public_logs,
    )
    .unwrap();
    let next = next_block_with_protocol_config(store, config).await;
    let base = next.header();
    let reference = BlockHeader::new(
        base.prev_block_commitment(),
        base.block_num(),
        base.chain_commitment(),
        base.account_root(),
        base.nullifier_root(),
        base.code_tree_root(),
        body.compute_block_note_tree().root(),
        body.compute_transactions_commitment(),
        base.validator_config().clone(),
        base.fee_parameters().clone(),
        base.protocol_config_commitment(),
        None,
        base.timestamp(),
    );
    store
        .writer
        .apply_block(
            SignedBlock::new_unchecked(
                reference.clone(),
                body,
                BlockSignatures::new(vec![]).unwrap(),
            ),
            None,
        )
        .await
        .unwrap();
    (reference, tx)
}
