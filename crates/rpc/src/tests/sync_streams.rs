//! Cross-endpoint admission and concurrent-write acceptance checks.
use std::net::{IpAddr, Ipv4Addr};

use miden_node_utils::grpc::ClientIp;
use miden_protocol::note::Nullifier;
use miden_protocol::{Felt, Word};
use tokio_stream::StreamExt;

use super::*;

/// Pins prefix discovery to genesis and assigns a client address for admission checks.
fn request(client: u8) -> Request<proto::miden::node::v1::SyncNullifiersV2Request> {
    let mut request = Request::new(proto::miden::node::v1::SyncNullifiersV2Request {
        range: Some(proto::miden::node::v1::StateDeltaRange {
            from_block_exclusive: None,
            to_block_inclusive: Some(0),
        }),
        prefix_len: 16,
        nullifiers: vec![1],
    });
    request
        .extensions_mut()
        .insert(ClientIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, client))));
    request
}

fn nullifier(index: u64) -> Nullifier {
    Nullifier::from_raw(Word::from([
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::new_unchecked((1 << 48) + index),
    ]))
}

/// Slow and disconnected readers must not block fast readers or committed block writes.
///
/// Each successful reader must obtain the exact pinned result set. Stalled readers must fail explicitly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_readers_preserve_targets_and_leave_block_writes_available() {
    let mut store = TestStore::start().await;
    let path = store.data_directory_path().join("miden-store.sqlite3");
    let expected: HashSet<_> = (0..1024).map(nullifier).collect();
    miden_node_store::test_support::seed_nullifiers(
        &path,
        0.into(),
        expected.iter().copied().collect(),
    )
    .await;
    let (genesis, _) = store.state.view().get_block_header(Some(0.into()), false).await.unwrap();
    let config = store
        .state
        .view()
        .get_protocol_config(genesis.unwrap().protocol_config_commitment())
        .await
        .unwrap()
        .unwrap();
    let service = RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::full_node(source_rpc_client(), None),
        None,
        NonZeroUsize::MIN,
        None,
    );
    let mut slow = service.sync_nullifiers_v2(request(1)).await.unwrap().into_inner();
    let disconnected = service.sync_nullifiers_v2(request(1)).await.unwrap();
    let status = service.sync_nullifiers_v2(request(1)).await.err().unwrap();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    drop(disconnected);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match service.sync_nullifiers_v2(request(1)).await {
                Ok(stream) => {
                    drop(stream);
                    break;
                },
                Err(status) => {
                    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
                    tokio::task::yield_now().await;
                },
            }
        }
    })
    .await
    .expect("disconnect releases admission promptly");
    let mut fast_a = service.sync_nullifiers_v2(request(2)).await.unwrap().into_inner();
    let mut fast_b = service.sync_nullifiers_v2(request(3)).await.unwrap().into_inner();
    let read = async |stream: &mut <RpcService as Api>::SyncNullifiersV2Stream| {
        let mut found = HashSet::new();
        while let Some(item) = stream.next().await {
            let item = item.unwrap();
            assert_eq!(item.block_num, 0);
            assert!(
                found.insert(Nullifier::from_raw(item.nullifier.unwrap().decode_fields().unwrap()))
            );
        }
        found
    };
    let writer = async {
        let block = next_block_with_protocol_config(&store, &config).await;
        store.writer.apply_block(block, None).await.unwrap();
        miden_node_store::test_support::seed_nullifiers(&path, 1.into(), vec![nullifier(2048)])
            .await;
    };
    let (found_a, found_b, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(read(&mut fast_a), read(&mut fast_b), writer)
    })
    .await
    .expect("fast readers and block writes progress while slow reader blocks");
    assert_eq!(found_a, expected);
    assert_eq!(found_b, expected);
    assert_eq!(*store.state.view().tip(), BlockNumber::from(1));
    // The reserved terminal slot must report timeout instead of successful truncation.
    tokio::time::sleep(Duration::from_secs(11)).await;
    let mut count = 0;
    let mut failed = false;
    while let Some(item) = slow.next().await {
        match item {
            Ok(item) => {
                assert_eq!(item.block_num, 0);
                count += 1;
            },
            Err(status) => {
                assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
                failed = true;
            },
        }
    }
    assert!(failed);
    assert!(count <= 32, "only the configured data buffer is retained");
    let mut retry = service.sync_nullifiers_v2(request(1)).await.unwrap().into_inner();
    assert_eq!(read(&mut retry).await, expected);
}
