use std::net::SocketAddr;

use miden_node_proto::clients::ForeignAccount;
use miden_protocol::Word;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::TransactionId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::*;
use crate::db::{DatabaseIdentity, FundingDatabase, TransactionAttempt};
use crate::node::tests::{TestChain, TestServer};
use crate::test_utils::Fixture;

async fn http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn startup_serves_the_loaded_balance_and_accepts_requests_while_recovery_waits() {
    let balance = 1_000_000;
    let base_fee = 3;
    let fixture = Fixture::new(balance, base_fee).unwrap();
    let fee_asset_id = AssetId::new_fungible(fixture.fee_faucet_id);
    let chain = fixture.chain.lock().await;
    let initial_header = chain.latest_block_header();
    let protocol_config = chain.protocol_config().clone();
    let faucet = chain.committed_account(fixture.fee_faucet_id).unwrap().clone();
    let witness = chain
        .account_witnesses([fixture.fee_faucet_id])
        .remove(&fixture.fee_faucet_id)
        .unwrap();
    drop(chain);
    let fee_faucet = UsdcxFaucet::new(ForeignAccount::from_account(faucet, witness));
    let native_asset = NativeAsset::new(fee_asset_id, &fee_faucet.metadata().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(lifecycle::DATABASE_FILENAME);
    let identity = DatabaseIdentity {
        genesis_commitment: Word::empty(),
        funding_account_id: fixture.wallet.account_id(),
        fee_asset_id,
    };
    let database = FundingDatabase::bootstrap(&path, identity).await.unwrap();
    let target = ACCOUNT_ID_SENDER.try_into().unwrap();
    let note = database.store_request(target, 1_000, Word::from([1u32; 4])).await.unwrap();
    let attempt = TransactionAttempt {
        transaction_id: TransactionId::from_raw(Word::empty()),
        reference_block: initial_header.block_num(),
        expiration_block: initial_header.block_num() + 50,
        deposit_nullifier: None,
        note_ids: vec![note.note.id()],
    };
    database.start_attempt(attempt.clone()).await.unwrap();
    let mut rpc_chain = TestChain::new(10);
    rpc_chain.unavailable_for = Some(("SyncTransactions", 1));
    let rpc = TestServer::start(rpc_chain).await;
    let initial_block = initial_header.block_num();
    let service = FundingService {
        database,
        node: rpc.node.clone(),
        prover: Prover::local(),
        wallet: fixture.wallet,
        initial_header,
        fee_asset_id,
        native_asset,
        fee_faucet,
        protocol_config,
        worker_config: WorkerConfig {
            max_notes_per_tx: DEFAULT_MAX_NOTES_PER_TX,
            expiration_delta: DEFAULT_TX_EXPIRATION_DELTA,
            poll_interval: Duration::from_millis(1),
        },
        max_amount: balance,
        http_timeout: DEFAULT_HTTP_TIMEOUT,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(service.run(listener, shutdown.clone()));
    tokio::time::timeout(Duration::from_secs(5), async {
        while rpc.chain.lock().unwrap().unavailable_for.unwrap().1 != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    let (status, body) = http_request(address, "GET", "/status", "").await;
    assert_eq!(status, 200);
    assert_eq!(body["balance"], balance);
    assert_eq!(body["verification_base_fee"], base_fee);
    assert_eq!(body["chain_tip"], initial_block.as_u32());
    let request = serde_json::json!({ "account_id": target.to_hex(), "amount": 1_000 }).to_string();
    let (status, body) = http_request(address, "POST", "/request-funds", &request).await;
    assert_eq!(status, 200);
    let accepted =
        Note::read_from_bytes(&hex::decode(body["note"].as_str().unwrap()).unwrap()).unwrap();
    let database =
        FundingDatabase::open_and_verify(&path, identity.genesis_commitment, fee_asset_id)
            .await
            .unwrap();
    assert_eq!(database.request(accepted.id()).await.unwrap().unwrap().note, accepted);
    assert_eq!(database.active_attempt().await.unwrap(), Some(attempt));

    let request =
        serde_json::json!({ "account_id": target.to_hex(), "amount": balance }).to_string();
    let (status, _) = http_request(address, "POST", "/request-funds", &request).await;
    assert_eq!(status, 412);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
