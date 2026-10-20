use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::BoxFuture;
use miden_node_proto::DecodeMessageExt;
use miden_node_proto::domain::account::{
    AccountDetails,
    AccountStorageDetails,
    AccountVaultDetails,
    AccountVaultRequest,
    GetAccountResponse,
};
use miden_node_proto::generated::miden::node::v1 as rpc;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountHeader, AccountType};
use miden_protocol::asset::{
    Asset,
    AssetId,
    AssetVault,
    NonFungibleAsset,
    NonFungibleAssetDetails,
    PartialVault,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::testing::account_id::AccountIdBuilder;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic_prost::ProstCodec;
use tower::Service;

use super::RpcClient;
use crate::test_utils::{mock_account, mock_network_account_id};

#[derive(Clone, Copy, Default)]
enum ResponseFault {
    #[default]
    None,
    LimitExceeded,
    MissingAsset,
    WrongBlock,
    WrongAccount,
    WrongRoot,
}

#[derive(Clone)]
struct VaultRpc {
    account: Account,
    requests: Arc<Mutex<Vec<Vec<AssetId>>>>,
    full_vault: bool,
    fault: ResponseFault,
}

impl UnaryService<rpc::GetAccountRequest> for VaultRpc {
    type Response = rpc::GetAccountResponse;
    type Future = Ready<tonic::Result<tonic::Response<Self::Response>>>;

    fn call(&mut self, request: tonic::Request<rpc::GetAccountRequest>) -> Self::Future {
        let request = request.into_inner().decode_and_verify().unwrap();
        let AccountVaultRequest::Assets(mut asset_ids) = request.details.unwrap().vault_request
        else {
            panic!("expected a selective vault request")
        };
        self.requests.lock().unwrap().push(asset_ids.clone());
        assert!(asset_ids.len() <= AccountVaultDetails::MAX_PROOF_ENTRIES);
        assert_eq!(request.account_id, self.account.id());
        assert_eq!(request.block_num, Some(BlockNumber::from(7)));

        let mut header = AccountHeader::from(&self.account);
        let mut block_num = request.block_num.unwrap();
        match self.fault {
            ResponseFault::MissingAsset => {
                asset_ids.pop();
            },
            ResponseFault::WrongBlock => {
                block_num = block_num.child();
            },
            ResponseFault::WrongAccount => {
                let id = AccountIdBuilder::new()
                    .account_type(AccountType::Public)
                    .build_with_seed([99; 32]);
                header = AccountHeader::new(
                    id,
                    header.nonce(),
                    header.vault_root(),
                    header.storage_commitment(),
                    header.code_commitment(),
                );
            },
            _ => {},
        }
        let vault = if matches!(self.fault, ResponseFault::WrongRoot) {
            AssetVault::default()
        } else {
            self.account.vault().clone()
        };
        if matches!(self.fault, ResponseFault::WrongRoot) {
            header = AccountHeader::new(
                header.id(),
                header.nonce(),
                vault.root(),
                header.storage_commitment(),
                header.code_commitment(),
            );
        }
        let vault_details = if matches!(self.fault, ResponseFault::LimitExceeded) {
            AccountVaultDetails::LimitExceeded
        } else if self.full_vault {
            let mut assets = vault.assets().collect::<Vec<_>>();
            if matches!(self.fault, ResponseFault::MissingAsset) {
                assets.pop();
            }
            AccountVaultDetails::from_assets(assets)
        } else {
            let partial = if asset_ids.is_empty() {
                PartialVault::new(vault.root())
            } else {
                PartialVault::with_witnesses(asset_ids.iter().map(|id| vault.open(*id))).unwrap()
            };
            AccountVaultDetails::Partial { asset_ids, vault: partial }
        };
        let witness = AccountTree::with_entries([(header.id(), header.to_commitment())])
            .unwrap()
            .open(header.id());
        ready(Ok(tonic::Response::new(
            GetAccountResponse {
                block_num,
                witness,
                details: Some(AccountDetails {
                    account_header: header,
                    account_code: None,
                    vault_details,
                    storage_details: AccountStorageDetails {
                        header: self.account.storage().to_header(),
                        map_details: vec![],
                    },
                }),
            }
            .into(),
        )))
    }
}

impl NamedService for VaultRpc {
    const NAME: &'static str = "miden.node.v1.NodeService";
}

impl Service<http::Request<Body>> for VaultRpc {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        assert_eq!(request.uri().path(), "/miden.node.v1.NodeService/GetAccount");
        let reply = self.clone();
        Box::pin(async move { Ok(Grpc::new(ProstCodec::default()).unary(reply, request).await) })
    }
}

struct TestServer {
    client: RpcClient,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(service: VaultRpc) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let client = RpcClient::new(
            format!("http://{address}").parse().unwrap(),
            Word::default(),
            vec![],
            Duration::from_secs(10),
            Duration::from_millis(10),
            Duration::from_millis(100),
            miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
        )
        .unwrap();
        Self { client, task }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn account_with_vault(num_assets: usize) -> (Account, Vec<AssetId>) {
    let faucet = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([7; 32]);
    let assets = (0..num_assets)
        .map(|i| {
            Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
                faucet,
                (i as u64).to_le_bytes().to_vec(),
            )))
        })
        .collect::<Vec<_>>();
    let account = mock_account(mock_network_account_id());
    let account = Account::new(
        account.id(),
        AssetVault::new(&assets).unwrap(),
        account.storage().clone(),
        account.code().clone(),
        account.nonce(),
        None,
    )
    .unwrap();
    let absent = NonFungibleAsset::new(&NonFungibleAssetDetails::new(faucet, vec![255]));
    let mut ids = assets
        .iter()
        .take(AccountVaultDetails::MAX_PROOF_ENTRIES)
        .map(Asset::id)
        .collect::<Vec<_>>();
    ids.push(Asset::from(absent).id());
    (account, ids)
}

#[tokio::test]
async fn witnesses_for_large_vault_are_fetched_in_bounded_batches() {
    let (account, ids) = account_with_vault(AccountVaultDetails::MAX_RETURN_ENTRIES + 1);
    let requested = ids.into_iter().collect::<BTreeSet<_>>();
    let requests = Arc::default();
    let server = TestServer::start(VaultRpc {
        account: account.clone(),
        requests: Arc::clone(&requests),
        full_vault: false,
        fault: ResponseFault::None,
    })
    .await;
    let witnesses = server
        .client
        .get_vault_asset_witnesses(
            account.id(),
            account.vault().root(),
            requested.clone(),
            7.into(),
        )
        .await
        .unwrap();
    assert_eq!(
        witnesses,
        requested.iter().map(|id| account.vault().open(*id)).collect::<Vec<_>>()
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(
        requests.lock().unwrap().iter().flatten().copied().collect::<BTreeSet<_>>(),
        requested
    );

    let empty = server
        .client
        .get_vault_asset_witnesses(account.id(), account.vault().root(), BTreeSet::new(), 7.into())
        .await
        .unwrap();
    assert!(empty.is_empty());
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn witnesses_can_be_derived_from_full_vault_responses() {
    for num_assets in [0, 10] {
        let (account, ids) = account_with_vault(num_assets);
        let requested = BTreeSet::from([ids[0], *ids.last().unwrap()]);
        let server = TestServer::start(VaultRpc {
            account: account.clone(),
            requests: Arc::default(),
            full_vault: true,
            fault: ResponseFault::None,
        })
        .await;
        let witnesses = server
            .client
            .get_vault_asset_witnesses(
                account.id(),
                account.vault().root(),
                requested.clone(),
                7.into(),
            )
            .await
            .unwrap();
        assert_eq!(
            witnesses,
            requested.into_iter().map(|id| account.vault().open(id)).collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn witnesses_reject_incomplete_or_mismatched_responses() {
    let (account, ids) = account_with_vault(10);
    for (full_vault, fault) in [false, true].into_iter().flat_map(|full| {
        [
            ResponseFault::LimitExceeded,
            ResponseFault::MissingAsset,
            ResponseFault::WrongBlock,
            ResponseFault::WrongAccount,
            ResponseFault::WrongRoot,
        ]
        .into_iter()
        .map(move |fault| (full, fault))
    }) {
        let server = TestServer::start(VaultRpc {
            account: account.clone(),
            requests: Arc::default(),
            full_vault,
            fault,
        })
        .await;
        let result = server
            .client
            .get_vault_asset_witnesses(
                account.id(),
                account.vault().root(),
                BTreeSet::from([ids[0]]),
                7.into(),
            )
            .await;
        assert!(result.is_err(), "unexpected result: {result:?}");
    }
}
