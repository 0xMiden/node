use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_node_store::GenesisState;
use miden_node_store::state::State;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::{BlockHeader, BlockNumber, ValidatorConfig};
use miden_protocol::testing::random_secret_key::random_secret_key;
use url::Url;

use crate::domain::transaction::AuthenticatedTransaction;
use crate::mempool::{Mempool, MempoolConfig};
use crate::server::MempoolStats;
use crate::test_utils::MockProvenTxBuilder;
use crate::test_utils::batch::TransactionBatchConstructor;
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
    let tx = Arc::new(AuthenticatedTransaction::from_inner(
        MockProvenTxBuilder::with_account_index(100).build(),
    ));

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

    mempool.commit_batch(Arc::new(ProvenBatch::mocked_from_transactions([
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

#[tokio::test]
async fn block_producer_starts_with_store_state() {
    let data_directory = tempfile::tempdir().expect("tempdir should be created");
    bootstrap_store(data_directory.path());
    let (state, block_writer, proof_writer) = State::for_tests(data_directory.path()).await;

    let block_producer = Sequencer {
        state,
        block_writer,
        proof_writer,
        validator_urls: vec![Url::parse("http://127.0.0.1:0").unwrap()],
        validator_timeout: DEFAULT_VALIDATOR_TIMEOUT,
        batch_prover_url: None,
        block_prover_url: None,
        batch_interval: Duration::from_hours(1),
        block_interval: Duration::from_hours(1),
        max_txs_per_batch: DEFAULT_MAX_TXS_PER_BATCH,
        max_batches_per_block: DEFAULT_MAX_BATCHES_PER_BLOCK,
        max_concurrent_proofs: DEFAULT_MAX_CONCURRENT_PROOFS,
        mempool_tx_capacity: NonZeroUsize::new(100).unwrap(),
        batch_workers: DEFAULT_BATCH_WORKERS,
    }
    .spawn(miden_node_utils::shutdown::CancellationToken::new())
    .unwrap();

    let status = block_producer.api().status().await;
    assert_eq!(status.status, "connected");
    assert_eq!(status.chain_tip, BlockNumber::GENESIS);
}

fn bootstrap_store(path: &std::path::Path) {
    let signer = random_secret_key();
    let genesis_state = GenesisState::new(
        vec![],
        test_fee_params(),
        1,
        1,
        ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
        test_protocol_config(),
    );
    let genesis_block = genesis_state.into_block().expect("genesis block should be created");

    State::bootstrap(genesis_block, path).expect("store should bootstrap");
}
