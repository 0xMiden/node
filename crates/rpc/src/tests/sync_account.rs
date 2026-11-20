use miden_protocol::Felt;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountCodePatch,
    AccountComponent,
    AccountHeader,
    AccountStorage,
    AccountStoragePatch,
    AccountVaultPatch,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::block::{BlockAccountUpdate, BlockBody, BlockHeader};
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_standards::code_builder::CodeBuilder;
use v2::node_service_server::NodeService as V2Api;

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

fn service(store: &TestStore) -> RpcService {
    RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::full_node(source_rpc_client(), None),
        None,
        NonZeroUsize::MIN,
        None,
    )
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
async fn v2_account_infos() {
    use v2::get_account_infos_request::AccountQuery;
    use v2::get_account_infos_response::account_info::Result as Info;
    let initial = account(1, 0, 1);
    let (mut store, _, config) = fixture(&initial).await;
    let block = next_block_with_protocol_config(&store, &config).await;
    store.writer.apply_block(block, None).await.unwrap();
    let rpc = service(&store);
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
    let rpc = service(&store);
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
    for count in [1, 65] {
        let (account, empty_map, value_slot) = entry_witness_account(count);
        let (mut store, genesis, config) = fixture(&account).await;
        let asset = account.vault().assets().next().unwrap();
        let mut updated = account.clone();
        let patch = AccountPatch::new(
            account.id(),
            AccountStoragePatch::default(),
            AccountVaultPatch::new(BTreeMap::from([(asset.id(), Word::empty())])).unwrap(),
            AccountCodePatch::default(),
            Some(account.nonce() + Felt::ONE),
        )
        .unwrap();
        apply(&mut store, &genesis, &config, &mut updated, patch).await;
        assert_ne!(updated.to_header().vault_root(), account.to_header().vault_root());
        let rpc = service(&store);
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
