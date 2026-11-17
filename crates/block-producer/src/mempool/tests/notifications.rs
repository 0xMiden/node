use std::sync::Arc;

use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::{BlockHeader, BlockNumber};
use tokio::sync::watch;

use crate::domain::batch::BatchParameters;
use crate::mempool::{Mempool, MempoolConfig};
use crate::test_utils::MockProvenTxBuilder;
use crate::test_utils::batch::TransactionBatchConstructor;

fn assert_update(updates: &mut watch::Receiver<usize>, count: usize) {
    assert!(updates.has_changed().unwrap(), "mempool mutation must notify subscribers");
    assert_eq!(*updates.borrow_and_update(), count);
    assert!(!updates.has_changed().unwrap());
}

#[test]
fn admission_and_selection_publish_the_latest_unbatched_count() {
    let mempool = Mempool::shared(BlockNumber::GENESIS, MempoolConfig::default());
    let mut updates = mempool.subscribe().unwrap();
    assert_eq!(*updates.borrow_and_update(), 0);
    let [first, second, _] = MockProvenTxBuilder::sequential();

    mempool.lock().unwrap().add_transaction(first).unwrap();
    mempool.lock().unwrap().add_transaction(second).unwrap();
    assert_update(&mut updates, 2);
    let late_subscriber = mempool.subscribe().unwrap();
    assert_eq!(*late_subscriber.borrow(), 2);

    mempool.lock().unwrap().select_any_batch().unwrap();
    assert_update(&mut updates, 0);
}

#[test]
fn batch_rollback_and_proof_completion_notify_subscribers() {
    let (mut pool, _) = Mempool::for_tests();
    let mut updates = pool.updates.subscribe();
    let [first, _, _] = MockProvenTxBuilder::sequential();
    pool.add_transaction(first.clone()).unwrap();
    let batch = pool.select_any_batch().unwrap();
    assert_update(&mut updates, 0);

    pool.rollback_batch(batch.id());
    assert_update(&mut updates, 1);
    pool.select_any_batch().unwrap();
    assert_update(&mut updates, 0);
    pool.commit_batch(Arc::new(ProvenBatch::mocked_from_transactions([
        first.raw_proven_transaction()
    ])));
    assert_update(&mut updates, 0);
}

#[test]
fn block_rollback_and_commit_notify_subscribers() {
    let (mut pool, _) = Mempool::for_tests();
    let mut updates = pool.updates.subscribe();
    let [first, _, _] = MockProvenTxBuilder::sequential();
    pool.add_transaction(first.clone()).unwrap();
    pool.select_any_batch().unwrap();
    let proof = Arc::new(ProvenBatch::mocked_from_transactions([first.raw_proven_transaction()]));
    pool.commit_batch(proof.clone());
    assert_update(&mut updates, 0);

    let block = pool.select_block();
    assert_update(&mut updates, 0);
    pool.rollback_block(block.block_number);
    assert_update(&mut updates, 1);

    pool.select_any_batch().unwrap();
    pool.commit_batch(proof);
    let block = pool.select_block();
    assert_update(&mut updates, 0);
    pool.commit_block(&BlockHeader::mock(block.block_number, None, None, &[]));
    assert_update(&mut updates, 0);
}

#[test]
fn user_batch_admission_notifies_even_when_it_is_promoted_immediately() {
    let (mut pool, _) = Mempool::for_tests();
    let mut updates = pool.updates.subscribe();
    let [first, _, _] = MockProvenTxBuilder::sequential();
    let proof = Arc::new(ProvenBatch::mocked_from_transactions([first.raw_proven_transaction()]));
    pool.add_user_batch(&[first], BatchParameters::for_tests(), proof).unwrap();

    assert_update(&mut updates, 0);
    assert_eq!(pool.proven_batches_count(), 1);
}

#[test]
fn read_only_access_and_failed_operations_do_not_notify_subscribers() {
    let (mut pool, _) = Mempool::for_tests();
    pool.config.batch_budget.transactions = 2;
    let mut updates = pool.updates.subscribe();
    assert_eq!(pool.unbatched_transactions_count(), 0);
    assert!(pool.select_any_batch().is_none());
    assert!(pool.select_full_batch().is_none());
    assert!(!updates.has_changed().unwrap());

    let [first, _, _] = MockProvenTxBuilder::sequential();
    pool.add_transaction(first.clone()).unwrap();
    assert_update(&mut updates, 1);
    assert!(pool.add_transaction(first).is_err());
    assert!(pool.select_full_batch().is_none());
    assert!(!updates.has_changed().unwrap());

    let batch = pool.select_any_batch().unwrap();
    pool.rollback_batch(batch.id());
    assert_update(&mut updates, 1);
    pool.rollback_batch(batch.id());
    assert!(!updates.has_changed().unwrap());
}

#[test]
fn cloned_mempools_publish_independently() {
    let (mut pool, _) = Mempool::for_tests();
    let [first, _, _] = MockProvenTxBuilder::sequential();
    pool.add_transaction(first).unwrap();
    let mut cloned = pool.clone();
    let original_updates = pool.updates.subscribe();
    let mut cloned_updates = cloned.updates.subscribe();
    assert_eq!(*cloned_updates.borrow(), 1);

    cloned.select_any_batch().unwrap();
    assert_update(&mut cloned_updates, 0);
    assert!(!original_updates.has_changed().unwrap());
    assert_eq!(*original_updates.borrow(), 1);
}
