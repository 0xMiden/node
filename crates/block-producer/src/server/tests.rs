use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_node_store::GenesisState;
use miden_node_store::state::State;
use miden_node_utils::fee::test_fee_params;
use miden_protocol::ONE;
use miden_protocol::account::Account;
use miden_protocol::asset::AssetId;
use miden_protocol::block::{BlockHeader, BlockNumber, ValidatorConfig};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::testing::random_secret_key::random_secret_key;
use url::Url;

use crate::mempool::{Mempool, MempoolConfig};
use crate::server::MempoolStats;
use crate::test_utils::batch::mock_proven_batch_with_fee_collection;
use crate::test_utils::{MockAuthenticatedTxBuilder, MockProvenTxBuilder};
use crate::{
    DEFAULT_BATCH_WORKERS,
    DEFAULT_MAX_BATCHES_PER_BLOCK,
    DEFAULT_MAX_CONCURRENT_PROOFS,
    DEFAULT_MAX_TXS_PER_BATCH,
    DEFAULT_VALIDATOR_TIMEOUT,
    Sequencer,
};

#[test]
fn mempool_stats_track_uncommitted_work_and_the_canonical_tip() {
    let shared = Mempool::shared(BlockNumber::GENESIS, MempoolConfig::default());
    let mut mempool = shared.lock().unwrap();
    let tx = Arc::new(
        MockAuthenticatedTxBuilder::new(MockProvenTxBuilder::with_account_index(100).build())
            .build(),
    );

    mempool.add_transaction(Arc::clone(&tx)).unwrap();
    let stats = MempoolStats::from_mempool(&mempool);
    assert_eq!(stats.chain_tip, BlockNumber::GENESIS);
    assert_eq!(stats.uncommitted_transactions, 1);
    assert_eq!(stats.unbatched_transactions, 1);
    assert_eq!(stats.proposed_batches, 0);
    assert_eq!(stats.proven_batches, 0);

    mempool.select_any_batch().unwrap();
    let stats = MempoolStats::from_mempool(&mempool);
    assert_eq!(stats.uncommitted_transactions, 1);
    assert_eq!(stats.unbatched_transactions, 0);
    assert_eq!(stats.proposed_batches, 1);
    assert_eq!(stats.proven_batches, 0);

    mempool.commit_batch(Arc::new(mock_proven_batch_with_fee_collection([
        tx.raw_proven_transaction()
    ])));
    let stats = MempoolStats::from_mempool(&mempool);
    assert_eq!(stats.proposed_batches, 0);
    assert_eq!(stats.proven_batches, 1);

    let block = mempool.select_block();
    let stats = MempoolStats::from_mempool(&mempool);
    assert_eq!(stats.chain_tip, BlockNumber::GENESIS);
    assert_eq!(stats.uncommitted_transactions, 1);
    assert_eq!(stats.proven_batches, 0);

    let header = BlockHeader::mock(block.block_number, None, None, &[]);
    mempool.commit_block(&header);
    let stats = MempoolStats::from_mempool(&mempool);
    assert_eq!(stats.chain_tip, BlockNumber::GENESIS.child());
    assert_eq!(stats.uncommitted_transactions, 0);
    assert_eq!(stats.proven_batches, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn block_producer_starts_with_store_state() {
    let data_directory = tempfile::tempdir().expect("tempdir should be created");
    let account_file = crate::test_utils::mock_collection_account();
    let mut deployed_account = account_file.account().clone();
    deployed_account.set_nonce(ONE).unwrap();
    bootstrap_store(data_directory.path(), deployed_account).await;
    let (state, block_writer, proof_writer) = State::for_tests(data_directory.path()).await;
    let shutdown = miden_node_utils::shutdown::CancellationToken::new();

    let block_producer = Sequencer {
        state,
        block_writer,
        proof_writer,
        validator_urls: vec![Url::parse("http://127.0.0.1:0").unwrap()],
        validator_timeout: DEFAULT_VALIDATOR_TIMEOUT,
        block_prover_url: None,
        batch_interval: Duration::from_hours(1),
        block_interval: Duration::from_hours(1),
        max_txs_per_batch: DEFAULT_MAX_TXS_PER_BATCH,
        max_batches_per_block: DEFAULT_MAX_BATCHES_PER_BLOCK,
        max_concurrent_proofs: DEFAULT_MAX_CONCURRENT_PROOFS,
        mempool_tx_capacity: NonZeroUsize::new(100).unwrap(),
        batch_workers: DEFAULT_BATCH_WORKERS,
        fee_collector_account: account_file,
        builder_account_id:
            miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE
                .try_into()
                .unwrap(),
    }
    .start(shutdown.clone())
    .await
    .unwrap();

    let status = block_producer.api().status().await;
    assert_eq!(status.status, "connected");
    assert_eq!(status.chain_tip, BlockNumber::GENESIS);
    shutdown.cancel();
    block_producer.wait().await.unwrap();
}

async fn bootstrap_store(path: &std::path::Path, account: Account) {
    let signer = random_secret_key();
    let faucet = crate::test_utils::mock_native_faucet();
    let config = ProtocolConfig::current(AssetId::new_fungible(faucet.id())).unwrap();
    let genesis_state = GenesisState::new(
        vec![account, faucet],
        test_fee_params(),
        1,
        ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
        config,
    );
    let genesis_block = genesis_state.into_block().expect("genesis block should be created");

    State::bootstrap(genesis_block, path).await.expect("store should bootstrap");
}
