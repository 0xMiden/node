use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent,
    AccountHeader,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
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
