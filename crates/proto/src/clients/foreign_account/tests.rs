use std::collections::HashMap;
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use futures::future::BoxFuture;
use miden_protocol::Felt;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent,
    AccountIdVersion,
    AccountStorage,
    AccountType,
    AssetCallbackFlag,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetVault;
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::testing::assembler::assemble_test_package;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic_prost::ProstCodec;
use tower::Service;

use super::*;
use crate::clients::Builder;
use crate::domain::account::{AccountStorageMapDetails, AccountVaultDetails};
use crate::generated::miden::node::v1 as rpc;

struct TestState {
    account: Option<(Account, AccountWitness)>,
    account_history: HashMap<BlockNumber, (Account, AccountWitness)>,
    omit_account_code: bool,
    account_requests: Mutex<Vec<rpc::GetAccountRequest>>,
    account_response_block: Option<BlockNumber>,
    unavailable: bool,
}

impl TestState {
    fn get_account(&self, request: &rpc::GetAccountRequest) -> rpc::GetAccountResponse {
        use miden_protocol::account::StorageSlotContent;

        use crate::domain::account::{
            AccountDetails,
            AccountStorageDetails,
            AccountStorageMapDetails,
            AccountStorageRequest,
            GetAccountResponse,
            SlotData,
        };

        self.account_requests.lock().unwrap().push(request.clone());
        let request = request.clone().decode_and_verify().unwrap();
        let (account, witness) = request
            .block_num
            .and_then(|block| self.account_history.get(&block))
            .or(self.account.as_ref())
            .unwrap();
        let requested = request.details.unwrap();
        let maps = account
            .storage()
            .slots()
            .iter()
            .filter_map(|slot| {
                let StorageSlotContent::Map(map) = slot.content() else {
                    return None;
                };
                let slot_data = match &requested.storage_request {
                    AccountStorageRequest::None => return None,
                    AccountStorageRequest::AllStorageMaps => SlotData::All,
                    AccountStorageRequest::Explicit(requests) => requests
                        .iter()
                        .find(|request| &request.slot_name == slot.name())?
                        .slot_data
                        .clone(),
                };
                Some(match slot_data {
                    SlotData::All => {
                        AccountStorageMapDetails::from_all_entries(slot.name().clone(), map)
                    },
                    SlotData::MapKeys(keys) => {
                        let proofs = keys.iter().map(|key| map.open(key).into()).collect();
                        AccountStorageMapDetails::from_proofs(
                            slot.name().clone(),
                            map.root(),
                            keys,
                            proofs,
                        )
                        .unwrap()
                    },
                })
            })
            .collect();
        GetAccountResponse {
            block_num: self.account_response_block.or(request.block_num).unwrap(),
            witness: witness.clone(),
            details: Some(AccountDetails {
                account_header: account.into(),
                account_code: requested
                    .code_commitment
                    .filter(|commitment| {
                        *commitment != account.code().commitment() && !self.omit_account_code
                    })
                    .map(|_| account.code().clone()),
                vault_details: if matches!(
                    requested.vault_request,
                    crate::domain::account::AccountVaultRequest::All(_)
                ) {
                    AccountVaultDetails::from_assets(account.vault().assets().collect())
                } else {
                    AccountVaultDetails::empty()
                },
                storage_details: AccountStorageDetails {
                    header: account.storage().to_header(),
                    map_details: maps,
                },
            }),
        }
        .into()
    }
}

#[derive(Clone)]
struct RpcFixture(Arc<Mutex<TestState>>);

impl UnaryService<rpc::GetAccountRequest> for RpcFixture {
    type Response = rpc::GetAccountResponse;
    type Future = Ready<tonic::Result<tonic::Response<Self::Response>>>;

    fn call(&mut self, request: tonic::Request<rpc::GetAccountRequest>) -> Self::Future {
        let state = self.0.lock().unwrap();
        ready(if state.unavailable {
            Err(tonic::Status::unavailable("retry"))
        } else {
            Ok(tonic::Response::new(state.get_account(request.get_ref())))
        })
    }
}

impl NamedService for RpcFixture {
    const NAME: &'static str = "miden.node.v1.NodeService";
}

impl Service<http::Request<Body>> for RpcFixture {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        assert_eq!(request.uri().path(), "/miden.node.v1.NodeService/GetAccount");
        let reply = self.clone();
        Box::pin(async move { Ok(Grpc::new(ProstCodec::default()).unary(reply, request).await) })
    }
}

struct TestServer {
    rpc: RpcClient,
    id: AccountId,
    block: BlockNumber,
    state: Arc<Mutex<TestState>>,
    task: JoinHandle<()>,
}

impl TestServer {
    async fn start() -> Result<Self> {
        let id = AccountId::dummy(
            [7; 15],
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        );
        let num_entries = AccountStorageMapDetails::MAX_RETURN_ENTRIES + 1;
        let map = StorageMap::with_entries((0..num_entries).map(|index| {
            (
                StorageMapKey::from_array([u32::try_from(index).unwrap(), 123, 456, 789]),
                Word::from([42u32; 4]),
            )
        }))?;
        let storage = AccountStorage::new(vec![StorageSlot::with_map(
            StorageSlotName::new("miden::test::map")?,
            map,
        )])?;
        let account =
            Account::new(id, AssetVault::default(), storage, AccountCode::mock(), Felt::ONE, None)?;
        let witness = AccountTree::with_entries([(id, account.to_commitment())])?.open(id);
        let state = Arc::new(Mutex::new(TestState {
            account: Some((account, witness)),
            account_history: HashMap::new(),
            omit_account_code: false,
            account_requests: Mutex::new(Vec::new()),
            account_response_block: None,
            unavailable: false,
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?).parse()?;
        let incoming = futures::stream::unfold(listener, |listener| async move {
            Some((listener.accept().await.map(|(stream, _)| stream), listener))
        });
        let service = RpcFixture(state.clone());
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let rpc = Builder::new(url)
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .without_otel_context_injection()
            .connect()
            .await?;
        Ok(Self { rpc, id, block: 1.into(), state, task })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn foreign_account_reads_only_requested_keys_from_large_maps() -> Result<()> {
    use miden_protocol::account::{StorageMapKey, StorageSlotType};

    let server = TestServer::start().await?;
    let block = server.block;
    let full_response = server
        .rpc
        .clone()
        .get_account(rpc::GetAccountRequest {
            account_id: Some(server.id.into()),
            block_num: Some(block.into()),
            details: Some(AccountDetailRequest {
                storage_request: Some(StorageRequest::AllStorageMaps(true)),
                ..Default::default()
            }),
        })
        .await?
        .into_inner()
        .decode_and_verify()?;
    assert!(
        full_response
            .details
            .unwrap()
            .storage_details
            .map_details
            .iter()
            .all(|map| matches!(map.entries, StorageMapEntries::LimitExceeded))
    );
    server.state.lock().unwrap().account_requests.lock().unwrap().clear();

    let foreign = ForeignAccount::load_at(&mut server.rpc.clone(), server.id, block).await?;
    let account = foreign.inputs().account();
    assert_eq!(account.storage().maps().count(), 0);
    let root = account
        .storage()
        .header()
        .slots()
        .find(|slot| slot.slot_type() == StorageSlotType::Map)
        .unwrap()
        .value();
    let present = StorageMapKey::from_array([1, 123, 456, 789]);
    let absent = StorageMapKey::from_array([u32::MAX, 123, 456, 789]);
    for (key, value) in [(present, Word::from([42u32; 4])), (absent, Word::empty())] {
        let proof = foreign.storage_map_witness(&mut server.rpc.clone(), block, root, key).await?;
        assert_eq!(proof.get(key), Some(value));
        assert_eq!(proof.proof().compute_root(), root);
    }
    let state = server.state.lock().unwrap();
    let requests = state.account_requests.lock().unwrap();
    assert!(!requests.is_empty());
    for request in requests.iter() {
        let request = request.clone().decode_and_verify()?;
        assert_eq!(request.block_num, Some(block));
        let details = request.details.unwrap();
        assert_eq!(details.vault_request, crate::domain::account::AccountVaultRequest::None);
        match details.storage_request {
            crate::domain::account::AccountStorageRequest::None => {},
            crate::domain::account::AccountStorageRequest::Explicit(maps) => {
                for map in maps {
                    let crate::domain::account::SlotData::MapKeys(keys) = map.slot_data else {
                        panic!("foreign account loading must not request full maps");
                    };
                    assert!(keys.iter().all(|key| *key == present || *key == absent));
                }
            },
            crate::domain::account::AccountStorageRequest::AllStorageMaps => {
                panic!("foreign account loading must not request full maps");
            },
        }
    }
    Ok(())
}

#[tokio::test]
async fn foreign_account_rejects_a_different_reference_block() -> Result<()> {
    let server = TestServer::start().await?;
    let block = server.block;
    let foreign = ForeignAccount::load_at(&mut server.rpc.clone(), server.id, block).await?;
    server.state.lock().unwrap().account_response_block = Some(block + 1);
    assert!(
        ForeignAccount::load_at(&mut server.rpc.clone(), server.id, block)
            .await
            .is_err()
    );
    let root = foreign.inputs().account().storage().header().map_slot_roots().next().unwrap();
    assert!(
        foreign
            .storage_map_witness(
                &mut server.rpc.clone(),
                block,
                root,
                miden_protocol::account::StorageMapKey::from_index(1)
            )
            .await
            .is_err()
    );
    Ok(())
}

/// Adds a later account state to the RPC fixture while preserving earlier block snapshots.
fn add_account_version(
    server: &TestServer,
    initial_block: BlockNumber,
    updated: Account,
) -> Result<BlockNumber> {
    let witness =
        AccountTree::with_entries([(updated.id(), updated.to_commitment())])?.open(updated.id());
    let mut state = server.state.lock().unwrap();
    let initial = state.account.clone().unwrap();
    state.account_history.insert(initial_block, initial);
    let next_block = initial_block + 1;
    state.account_history.insert(next_block, (updated, witness));
    Ok(next_block)
}

#[tokio::test]
async fn foreign_account_sync_reuses_code_and_preserves_existing_snapshots() -> Result<()> {
    use miden_protocol::account::StorageMapKey;

    let server = TestServer::start().await?;
    let block = server.block;
    let mut foreign = ForeignAccount::load_at(&mut server.rpc.clone(), server.id, block).await?;
    let original = foreign.clone();
    let code = original.inputs().account().code().commitment();
    let key = StorageMapKey::from_array([1, 123, 456, 789]);
    let old_root = original.inputs().account().storage().header().map_slot_roots().next().unwrap();
    let mut updated = server.state.lock().unwrap().account.as_ref().unwrap().0.clone();
    let slot = updated
        .storage()
        .to_header()
        .slots()
        .find(|slot| slot.value() == old_root)
        .unwrap()
        .name()
        .clone();
    let value = Word::from([73u32; 4]);
    updated.storage_mut().set_map_item(&slot, key, value)?;
    let next_block = add_account_version(&server, block, updated.clone())?;

    foreign.sync_to(&mut server.rpc.clone(), next_block).await?;
    assert_eq!(foreign.inputs().account().storage().header(), &updated.storage().to_header());
    assert_eq!(foreign.inputs().account().code().commitment(), code);
    assert_ne!(foreign.inputs().witness(), original.inputs().witness());
    assert_eq!(foreign.inputs().account().storage().maps().count(), 0);
    let new_root = updated.storage().get_item(&slot)?;
    assert_eq!(
        foreign
            .storage_map_witness(&mut server.rpc.clone(), next_block, new_root, key)
            .await?
            .get(key),
        Some(value)
    );
    assert_eq!(
        original
            .storage_map_witness(&mut server.rpc.clone(), block, old_root, key)
            .await?
            .get(key),
        Some(Word::from([42u32; 4]))
    );

    {
        let state = server.state.lock().unwrap();
        let requests = state.account_requests.lock().unwrap();
        let sync_request = requests
            .iter()
            .find(|request| request.block_num == Some(next_block.into()))
            .unwrap();
        let details = sync_request.details.as_ref().unwrap();
        assert_eq!(details.code_commitment, Some(code.into()));
        assert!(details.storage_request.is_none());
        assert!(details.vault_request.is_none());
    }
    foreign.sync_to(&mut server.rpc.clone(), next_block).await?;
    assert!(
        foreign
            .storage_map_witness(&mut server.rpc.clone(), block, new_root, key)
            .await
            .is_err()
    );
    assert!(
        original
            .storage_map_witness(&mut server.rpc.clone(), next_block, old_root, key)
            .await
            .is_err()
    );
    server.state.lock().unwrap().unavailable = true;
    assert!(foreign.sync_to(&mut server.rpc.clone(), next_block + 1).await.is_err());
    assert_eq!(foreign.inputs().account().storage().header(), &updated.storage().to_header());
    server.state.lock().unwrap().unavailable = false;
    foreign.sync_to(&mut server.rpc.clone(), block).await?;
    assert_eq!(foreign.inputs(), original.inputs());
    Ok(())
}

#[tokio::test]
async fn foreign_account_sync_loads_changed_code_and_rejects_missing_code() -> Result<()> {
    let server = TestServer::start().await?;
    let block = server.block;
    let mut foreign = ForeignAccount::load_at(&mut server.rpc.clone(), server.id, block).await?;
    let original = foreign.clone();
    let package = assemble_test_package(
        "foreign-account-replacement",
        "miden::test::replacement",
        "@account_procedure pub proc updated push.7 end",
    );
    let component = AccountComponent::new(
        package,
        vec![],
        AccountComponentMetadata::new("miden::test::replacement"),
    )?;
    let replacement = AccountCode::from_components(&[NoopAuthComponent.into(), component])?;
    let account = server.state.lock().unwrap().account.as_ref().unwrap().0.clone();
    let (id, vault, storage, _, nonce, seed) = account.into_parts();
    let updated = Account::new(id, vault, storage, replacement.clone(), nonce, seed)?;
    let next_block = add_account_version(&server, block, updated)?;

    server.state.lock().unwrap().omit_account_code = true;
    assert!(foreign.sync_to(&mut server.rpc.clone(), next_block).await.is_err());
    assert_eq!(foreign.inputs(), original.inputs());
    server.state.lock().unwrap().omit_account_code = false;
    foreign.sync_to(&mut server.rpc.clone(), next_block).await?;
    assert_eq!(foreign.inputs().account().code(), &replacement);
    assert_ne!(foreign.inputs().account().code(), original.inputs().account().code());
    Ok(())
}
