//! A reference client that resumes real account streams using only their block ranges.

use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountStorageRequest,
    AccountVaultRequest,
    GetAccountRequest,
};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent,
    AccountHeader,
    AccountStorage,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetVault;
use miden_standards::code_builder::CodeBuilder;
use tokio_stream::StreamExt;

use super::*;

/// Holds a completed scan prefix separately from the current incomplete block.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockStage<K, V> {
    staged: BTreeMap<K, V>,
    from_exclusive: Option<u32>,
    target: u32,
    completed_target: Option<u32>,
    pending_block: Option<u32>,
    pending: BTreeMap<K, Option<V>>,
}

impl<K: Ord, V> BlockStage<K, V> {
    fn new(staged: BTreeMap<K, V>, from_exclusive: Option<u32>, target: u32) -> Self {
        Self {
            staged,
            from_exclusive,
            target,
            completed_target: None,
            pending_block: None,
            pending: BTreeMap::new(),
        }
    }

    fn push(&mut self, block: u32, key: K, value: Option<V>) -> Result<(), &'static str> {
        if block > self.target
            || self.from_exclusive.is_some_and(|from| block <= from)
            || self.pending_block.is_some_and(|last| block < last)
        {
            return Err("invalid update block");
        }
        if self.pending_block != Some(block) {
            self.flush();
            self.from_exclusive = block.checked_sub(1);
            self.pending_block = Some(block);
        }
        self.pending.insert(key, value);
        Ok(())
    }

    fn flush(&mut self) {
        for (key, value) in std::mem::take(&mut self.pending) {
            if let Some(value) = value {
                self.staged.insert(key, value);
            } else {
                self.staged.remove(&key);
            }
        }
        self.pending_block = None;
    }

    fn interrupt(&mut self) {
        self.pending.clear();
        self.pending_block = None;
    }

    fn retarget(&mut self, target: u32) -> Result<(), &'static str> {
        if target < self.target || self.pending_block.is_some() {
            return Err("invalid resumption target");
        }
        self.target = target;
        Ok(())
    }

    fn finish(&mut self) {
        self.flush();
        self.from_exclusive = Some(self.target);
        self.completed_target = Some(self.target);
    }

    fn range(&self) -> proto::miden::node::v1::StateDeltaRange {
        proto::miden::node::v1::StateDeltaRange {
            from_block_exclusive: self.from_exclusive,
            to_block_inclusive: Some(self.target),
        }
    }
}

type VaultStage = BlockStage<AssetId, Asset>;
type MapStage = BlockStage<(StorageSlotName, StorageMapKey), Word>;

fn stage_asset(stage: &mut VaultStage, item: proto::miden::node::v1::SyncAccountVaultV2Response) {
    let key: Word = item.vault_key.unwrap().decode_fields().unwrap();
    let asset = item.asset.map(|asset| asset.decode_fields().unwrap().verify().unwrap());
    stage.push(item.last_updated_at, key.try_into().unwrap(), asset).unwrap();
}

fn stage_map(stage: &mut MapStage, item: proto::miden::node::v1::SyncAccountStorageMapsV2Response) {
    let key: Word = item.key.unwrap().decode_fields().unwrap();
    let value: Word = item.value.unwrap().decode_fields().unwrap();
    stage
        .push(
            item.last_updated_at,
            (item.slot_name.parse().unwrap(), StorageMapKey::new(key)),
            (value != Word::empty()).then_some(value),
        )
        .unwrap();
}

fn service(store: &TestStore) -> RpcService {
    RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::full_node(source_rpc_client(), None),
        None,
        NonZeroUsize::MIN,
        None,
    )
}

async fn advance_to(store: &mut TestStore, target: u32) {
    let (header, _) = store.state.view().get_block_header(None, false).await.unwrap();
    let header = header.unwrap();
    let config = store
        .state
        .view()
        .get_protocol_config(header.protocol_config_commitment())
        .await
        .unwrap()
        .unwrap();
    while store.state.view().tip().as_u32() < target {
        let block = next_block_with_protocol_config(store, &config).await;
        store.writer.apply_block(block, None).await.unwrap();
    }
}

/// A disconnected vault scan must replay its partial block without losing the completed prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vault_sync_resumption_replays_interrupted_rpc_block() {
    let mut store = TestStore::start().await;
    let db = store.data_directory_path().join("miden-store.sqlite3");
    let account: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let values = vault_stream_values(602);
    advance_to(&mut store, 1).await;
    miden_node_store::test_support::seed_account_vault(&db, account, 1.into(), &values[..2]).await;
    advance_to(&mut store, 3).await;
    miden_node_store::test_support::seed_account_vault(&db, account, 3.into(), &values[2..]).await;
    let rpc = service(&store);
    let mut stage = VaultStage::new(BTreeMap::new(), Some(0), 3);
    let mut stream = rpc
        .sync_account_vault_v2(Request::new(proto::miden::node::v1::SyncAccountVaultV2Request {
            account_id: Some(account.into()),
            range: Some(stage.range()),
        }))
        .await
        .unwrap()
        .into_inner();
    loop {
        let item = stream.next().await.unwrap().unwrap();
        let block = item.last_updated_at;
        stage_asset(&mut stage, item);
        if block == 3 {
            break;
        }
    }
    drop(stream);
    stage.interrupt();
    assert_eq!(stage.from_exclusive, Some(2));
    assert_eq!(stage.staged.len(), 2);
    assert_eq!(stage.completed_target, None);
    advance_to(&mut store, 54).await;
    let old = rpc
        .sync_account_vault_v2(Request::new(proto::miden::node::v1::SyncAccountVaultV2Request {
            account_id: Some(account.into()),
            range: Some(stage.range()),
        }))
        .await
        .err()
        .expect("expired target must fail");
    assert_eq!(old.code(), tonic::Code::InvalidArgument);
    assert_eq!(old.details(), &[4]);
    stage.retarget(54).unwrap();
    let mut stream = rpc
        .sync_account_vault_v2(Request::new(proto::miden::node::v1::SyncAccountVaultV2Request {
            account_id: Some(account.into()),
            range: Some(stage.range()),
        }))
        .await
        .unwrap()
        .into_inner();
    let mut count = 0;
    while let Some(item) = stream.next().await {
        let item = item.unwrap();
        assert_eq!(item.last_updated_at, 3);
        stage_asset(&mut stage, item);
        count += 1;
    }
    stage.finish();
    assert_eq!(count, 600);
    assert_eq!(
        stage.staged,
        values.into_iter().map(|(key, value)| (key, value.unwrap())).collect()
    );
    assert_eq!(stage.completed_target, Some(54));
}

/// Map resumption preserves slot identity and replays every key in the interrupted block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_map_sync_resumption_replays_interrupted_rpc_block() {
    let mut store = TestStore::start().await;
    let db = store.data_directory_path().join("miden-store.sqlite3");
    let account: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let values: Vec<_> = (0_u32..602)
        .map(|n| {
            (
                StorageSlotName::mock((n % 2) as usize),
                StorageMapKey::new(Word::from([n / 2, 0, 0, 0])),
                Word::from([n + 1, 0, 0, 0]),
            )
        })
        .collect();
    for (block, entries) in [(1, &values[..2]), (3, &values[2..])] {
        advance_to(&mut store, block).await;
        miden_node_store::test_support::seed_account_vault(&db, account, block.into(), &[]).await;
        miden_node_store::test_support::seed_storage_map(&db, account, block.into(), entries).await;
    }
    let rpc = service(&store);
    let mut stage = MapStage::new(BTreeMap::new(), Some(0), 3);
    let mut stream = rpc
        .sync_account_storage_maps_v2(Request::new(
            proto::miden::node::v1::SyncAccountStorageMapsV2Request {
                account_id: Some(account.into()),
                range: Some(stage.range()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    loop {
        let item = stream.next().await.unwrap().unwrap();
        let block = item.last_updated_at;
        stage_map(&mut stage, item);
        if block == 3 {
            break;
        }
    }
    drop(stream);
    stage.interrupt();
    assert_eq!(stage.from_exclusive, Some(2));
    assert_eq!(stage.staged.len(), 2);
    advance_to(&mut store, 54).await;
    let old = rpc
        .sync_account_storage_maps_v2(Request::new(
            proto::miden::node::v1::SyncAccountStorageMapsV2Request {
                account_id: Some(account.into()),
                range: Some(stage.range()),
            },
        ))
        .await
        .err()
        .expect("expired target must fail");
    assert_eq!(old.code(), tonic::Code::InvalidArgument);
    assert_eq!(old.details(), &[4]);
    stage.retarget(54).unwrap();
    let mut stream = rpc
        .sync_account_storage_maps_v2(Request::new(
            proto::miden::node::v1::SyncAccountStorageMapsV2Request {
                account_id: Some(account.into()),
                range: Some(stage.range()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let mut count = 0;
    while let Some(item) = stream.next().await {
        let item = item.unwrap();
        assert_eq!(item.last_updated_at, 3);
        stage_map(&mut stage, item);
        count += 1;
    }
    stage.finish();
    assert_eq!(count, 600);
    assert_eq!(
        stage.staged,
        values.into_iter().map(|(slot, key, value)| ((slot, key), value)).collect()
    );
    assert_eq!(stage.completed_target, Some(54));
}

/// A terminal failure never authenticates or completes an otherwise valid downloaded prefix.
#[test]
fn sync_resumption_error_does_not_complete_target() {
    let mut stage = BlockStage::new(BTreeMap::from([(0, 10)]), Some(0), 100);
    let status =
        tonic::Status::with_details(tonic::Code::InvalidArgument, "target expired", vec![4].into());
    let responses = [Ok((40, 1, Some(11))), Ok((43, 2, Some(12))), Err(status)];
    let mut failed = false;
    for item in responses {
        if let Ok((block, key, value)) = item {
            stage.push(block, key, value).unwrap();
        } else {
            stage.interrupt();
            failed = true;
            break;
        }
    }
    if !failed {
        stage.finish();
    }
    assert!(failed);
    assert_eq!(stage.from_exclusive, Some(42));
    assert_eq!(stage.staged, BTreeMap::from([(0, 10), (1, 11)]));
    assert_eq!(stage.completed_target, None);
    stage.retarget(151).unwrap();
    stage.push(43, 2, Some(12)).unwrap();
    stage.push(101, 1, None).unwrap();
    stage.finish();
    assert_eq!(stage.staged, BTreeMap::from([(0, 10), (2, 12)]));
    assert_eq!(stage.completed_target, Some(151));
}

/// Invalid order or target changes cannot move a client's persisted checkpoint.
#[test]
fn sync_resumption_rejects_invalid_order_and_regressing_targets() {
    let mut stage = BlockStage::new(BTreeMap::new(), Some(10), 100);
    for block in [0, 10, 101] {
        let before = stage.clone();
        assert!(stage.push(block, 1, Some(1)).is_err());
        assert_eq!(stage, before);
    }
    stage.push(43, 1, Some(1)).unwrap();
    let before = stage.clone();
    assert!(stage.push(42, 2, None).is_err());
    assert!(stage.retarget(101).is_err());
    assert_eq!(stage, before);
    stage.interrupt();
    assert!(stage.retarget(99).is_err());
    assert_eq!(stage.target, 100);
}

/// Checkpoint restoration replays the pending block and never advances another endpoint.
#[test]
fn sync_resumption_checkpoints_are_independent() {
    let mut vault = BlockStage::new(BTreeMap::new(), None, 100);
    let maps = vault.clone();
    let another_account = vault.clone();
    vault.interrupt();
    assert_eq!(vault.from_exclusive, None);
    vault.push(0, 1, Some(11)).unwrap();
    vault.interrupt();
    assert_eq!(vault.from_exclusive, None);
    vault.push(0, 1, Some(11)).unwrap();
    vault.push(43, 2, Some(12)).unwrap();
    let mut restored = BlockStage::new(vault.staged.clone(), vault.from_exclusive, 151);
    assert_eq!(restored.from_exclusive, Some(42));
    restored.push(43, 2, Some(12)).unwrap();
    restored.finish();
    assert_eq!(restored.staged, BTreeMap::from([(1, 11), (2, 12)]));
    assert_eq!(restored.completed_target, Some(151));
    restored.retarget(200).unwrap();
    restored.finish();
    assert_eq!(restored.completed_target, Some(200));
    assert_eq!(restored.from_exclusive, Some(200));
    assert_eq!(maps.from_exclusive, None);
    assert_eq!(another_account.completed_target, None);
}

/// Replayed values must reconstruct the authenticated final account, not merely a matching row set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_resumption_authenticates_final_account_state() {
    let assets: Vec<_> =
        vault_stream_values(600).into_iter().map(|(_, asset)| asset.unwrap()).collect();
    let slot = StorageSlotName::mock(0);
    let entries: Vec<_> = (0_u32..600)
        .map(|n| (StorageMapKey::new(Word::from([n, 0, 0, 0])), Word::from([n + 1, 0, 0, 0])))
        .collect();
    let component = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code("resume::test", "@account_procedure pub proc read push.1 end")
            .unwrap(),
        vec![StorageSlot::with_map(
            slot.clone(),
            StorageMap::with_entries(entries.clone()).unwrap(),
        )],
        AccountComponentMetadata::new("resume"),
    )
    .unwrap();
    let account = AccountBuilder::new([51; 32])
        .account_type(AccountType::Public)
        .with_component(component)
        .with_component(NoopAuthComponent)
        .with_assets(assets)
        .build_existing()
        .unwrap();
    let mut builder = MockChainBuilder::new();
    builder.add_account(account.clone()).unwrap();
    let chain = builder.build().unwrap();
    let mut store =
        TestStore::start_from_mock_genesis(&chain.latest_block(), chain.protocol_config()).await;
    let rpc = service(&store);
    let mut vault = VaultStage::new(BTreeMap::new(), None, 0);
    let mut maps = MapStage::new(BTreeMap::new(), None, 0);
    let mut stream = rpc
        .sync_account_vault_v2(Request::new(proto::miden::node::v1::SyncAccountVaultV2Request {
            account_id: Some(account.id().into()),
            range: Some(vault.range()),
        }))
        .await
        .unwrap()
        .into_inner();
    stage_asset(&mut vault, stream.next().await.unwrap().unwrap());
    drop(stream);
    vault.interrupt();
    let mut stream = rpc
        .sync_account_storage_maps_v2(Request::new(
            proto::miden::node::v1::SyncAccountStorageMapsV2Request {
                account_id: Some(account.id().into()),
                range: Some(maps.range()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    stage_map(&mut maps, stream.next().await.unwrap().unwrap());
    drop(stream);
    maps.interrupt();
    advance_to(&mut store, 51).await;
    vault.retarget(51).unwrap();
    maps.retarget(51).unwrap();
    let mut stream = rpc
        .sync_account_vault_v2(Request::new(proto::miden::node::v1::SyncAccountVaultV2Request {
            account_id: Some(account.id().into()),
            range: Some(vault.range()),
        }))
        .await
        .unwrap()
        .into_inner();
    while let Some(item) = stream.next().await {
        stage_asset(&mut vault, item.unwrap());
    }
    vault.finish();
    let mut stream = rpc
        .sync_account_storage_maps_v2(Request::new(
            proto::miden::node::v1::SyncAccountStorageMapsV2Request {
                account_id: Some(account.id().into()),
                range: Some(maps.range()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    while let Some(item) = stream.next().await {
        stage_map(&mut maps, item.unwrap());
    }
    maps.finish();
    assert_authenticated_account_state(&store, account.id(), vault, maps, slot).await;
}

async fn assert_authenticated_account_state(
    store: &TestStore,
    account_id: AccountId,
    mut vault: VaultStage,
    maps: MapStage,
    slot: StorageSlotName,
) {
    let view = store.state.view();
    let (header, _) = view.get_block_header(Some(51.into()), false).await.unwrap();
    let root = header.unwrap().account_root();
    let response = view
        .get_account(GetAccountRequest {
            account_id,
            block_num: Some(51.into()),
            details: Some(AccountDetailRequest {
                code_commitment: None,
                vault_request: AccountVaultRequest::None,
                storage_request: AccountStorageRequest::None,
            }),
        })
        .await
        .unwrap();
    assert_eq!(response.block_num, 51.into());
    let leaf = response.witness.leaf();
    response
        .witness
        .path()
        .verify(leaf.index().position(), leaf.hash(), &root)
        .unwrap();
    let details = response.details.unwrap();
    let authenticated = details.account_header;
    assert_eq!(authenticated.to_commitment(), response.witness.state_commitment());
    assert_eq!(vault.staged.len(), 600);
    assert_eq!(maps.staged.len(), 600);
    let vault_root = AssetVault::new(&vault.staged.values().copied().collect::<Vec<_>>())
        .unwrap()
        .root();
    let map = StorageMap::with_entries(maps.staged.into_iter().map(|((name, key), value)| {
        assert_eq!(name, slot);
        (key, value)
    }))
    .unwrap();
    let storage = AccountStorage::new(vec![StorageSlot::with_map(slot, map)]).unwrap();
    let reconstructed = AccountHeader::new(
        authenticated.id(),
        authenticated.nonce(),
        vault_root,
        storage.to_commitment(),
        authenticated.code_commitment(),
    );
    assert_eq!(reconstructed.to_commitment(), response.witness.state_commitment());
    vault.staged.pop_first();
    let corrupted = AssetVault::new(&vault.staged.values().copied().collect::<Vec<_>>())
        .unwrap()
        .root();
    let corrupted = AccountHeader::new(
        authenticated.id(),
        authenticated.nonce(),
        corrupted,
        storage.to_commitment(),
        authenticated.code_commitment(),
    );
    assert_ne!(corrupted.to_commitment(), response.witness.state_commitment());
}
