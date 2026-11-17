use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use futures::{FutureExt, poll};
use miden_node_proto::domain::sequencer::TransactionCandidate;
use miden_node_tracing::span::{Attributes, Id};
use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::{BlockHeader, BlockNumber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

use super::*;
use crate::mempool::{Mempool, MempoolConfig};
use crate::test_utils::batch::TransactionBatchConstructor;
use crate::test_utils::{MockProvenTxBuilder, MockTransactionCandidateBuilder};

const INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Default)]
struct SelectionAttempts(Arc<AtomicUsize>);

impl Layer<Registry> for SelectionAttempts {
    fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, Registry>) {
        if attrs.metadata().target() == "miden::production::batches"
            && matches!(attrs.metadata().name(), "select_full_batch" | "select_any_batch")
        {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn mempool(max_transactions: usize) -> SharedMempool {
    let mut config = MempoolConfig::default();
    config.batch_budget.transactions = max_transactions;
    Mempool::shared(BlockNumber::GENESIS, config)
}

fn transaction(index: u32) -> Arc<TransactionCandidate> {
    Arc::new(
        MockTransactionCandidateBuilder::new(
            MockProvenTxBuilder::with_account_index(index).build(),
        )
        .build(),
    )
}

#[tokio::test(start_paused = true)]
async fn an_empty_mempool_does_not_poll_and_arrivals_wake_selection() {
    let mempool = mempool(2);
    let mut scheduler = BatchScheduler::new(mempool.clone(), INTERVAL).unwrap();
    let attempts = SelectionAttempts::default();
    let subscriber = Arc::new(Registry::default().with(attempts.clone()));
    let mut test = Box::pin(async {
        let mut next = Box::pin(scheduler.next_batch(true));
        assert!(poll!(next.as_mut()).is_pending());
        tokio::time::advance(Duration::from_hours(1)).await;
        assert!(poll!(next.as_mut()).is_pending());
        assert_eq!(attempts.0.load(Ordering::Relaxed), 0);

        let block = mempool.lock().unwrap().select_block();
        assert!(poll!(next.as_mut()).is_pending());
        mempool.lock().unwrap().commit_block(&BlockHeader::mock(
            block.block_number,
            None,
            None,
            &[],
        ));
        assert!(poll!(next.as_mut()).is_pending());
        assert_eq!(attempts.0.load(Ordering::Relaxed), 0);

        mempool.lock().unwrap().add_transaction(transaction(100)).unwrap();
        assert!(poll!(next.as_mut()).is_pending());
        tokio::time::advance(INTERVAL).await;
        let batch = next.await.unwrap();
        assert_eq!(batch.transactions().len(), 1);
        assert!(attempts.0.load(Ordering::Relaxed) > 0);
    });
    std::future::poll_fn(|cx| {
        let _subscriber = subscriber.clone().set_default();
        test.as_mut().poll(cx)
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_full_batch_is_selected_without_waiting_for_the_partial_deadline() {
    let mempool = mempool(2);
    let mut scheduler = BatchScheduler::new(mempool.clone(), INTERVAL).unwrap();
    let mut next = Box::pin(scheduler.next_batch(true));
    assert!(poll!(next.as_mut()).is_pending());
    mempool.lock().unwrap().add_transaction(transaction(101)).unwrap();
    assert!(poll!(next.as_mut()).is_pending());
    mempool.lock().unwrap().add_transaction(transaction(102)).unwrap();
    let Poll::Ready(Ok(batch)) = poll!(next.as_mut()) else {
        panic!("a full batch must be available immediately after admission");
    };
    assert_eq!(batch.transactions().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn new_arrivals_do_not_postpone_a_partial_batch() {
    let mempool = mempool(3);
    mempool.lock().unwrap().add_transaction(transaction(103)).unwrap();
    let mut scheduler = BatchScheduler::new(mempool.clone(), INTERVAL).unwrap();
    let mut next = Box::pin(scheduler.next_batch(true));
    assert!(poll!(next.as_mut()).is_pending());
    tokio::time::advance(INTERVAL / 2).await;
    mempool.lock().unwrap().add_transaction(transaction(104)).unwrap();
    assert!(poll!(next.as_mut()).is_pending());
    tokio::time::advance(INTERVAL / 2).await;
    let batch = next.await.unwrap();
    assert_eq!(batch.transactions().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn busy_workers_do_not_reserve_transactions_or_restart_the_partial_deadline() {
    let mempool = mempool(2);
    let mut scheduler = BatchScheduler::new(mempool.clone(), INTERVAL).unwrap();
    let mut busy = Box::pin(scheduler.next_batch(false));
    assert!(poll!(busy.as_mut()).is_pending());
    mempool.lock().unwrap().add_transaction(transaction(105)).unwrap();
    assert!(poll!(busy.as_mut()).is_pending());
    tokio::time::advance(INTERVAL * 2).await;
    assert!(poll!(busy.as_mut()).is_pending());
    assert_eq!(mempool.lock().unwrap().unbatched_transactions_count(), 1);
    drop(busy);

    let batch = scheduler
        .next_batch(true)
        .now_or_never()
        .expect("an overdue partial batch must be selected when a worker becomes available")
        .unwrap();
    assert_eq!(batch.transactions().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn batch_rollback_wakes_a_scheduler_waiting_on_zero_transactions() {
    let mempool = mempool(1);
    mempool.lock().unwrap().add_transaction(transaction(106)).unwrap();
    let selected = mempool.lock().unwrap().select_any_batch().unwrap();
    let mut scheduler = BatchScheduler::new(mempool.clone(), INTERVAL).unwrap();
    let mut next = Box::pin(scheduler.next_batch(true));
    assert!(poll!(next.as_mut()).is_pending());
    mempool.lock().unwrap().rollback_batch(selected.id());
    let batch = next
        .now_or_never()
        .expect("rollback must make the full batch selectable")
        .unwrap();
    assert_eq!(batch.transactions()[0].id(), selected.transactions()[0].id());
}

#[tokio::test(start_paused = true)]
async fn block_rollback_wakes_a_scheduler_waiting_on_zero_transactions() {
    let mempool = mempool(1);
    let tx = transaction(107);
    let block = {
        let mut pool = mempool.lock().unwrap();
        pool.add_transaction(tx.clone()).unwrap();
        pool.select_any_batch().unwrap();
        pool.commit_batch(Arc::new(ProvenBatch::mocked_from_transactions([
            tx.raw_proven_transaction()
        ])));
        pool.select_block()
    };
    assert_eq!(block.batches.len(), 1);
    let mut scheduler = BatchScheduler::new(mempool.clone(), INTERVAL).unwrap();
    let mut next = Box::pin(scheduler.next_batch(true));
    assert!(poll!(next.as_mut()).is_pending());
    mempool.lock().unwrap().rollback_block(block.block_number);
    let batch = next.now_or_never().expect("block rollback must wake batch selection").unwrap();
    assert_eq!(batch.transactions()[0].id(), tx.id());
}

#[tokio::test(start_paused = true)]
async fn updates_between_scheduler_calls_are_retained() {
    let mempool = mempool(2);
    let mut scheduler = BatchScheduler::new(mempool.clone(), INTERVAL).unwrap();
    assert!(scheduler.next_batch(true).now_or_never().is_none());
    mempool.lock().unwrap().add_transaction(transaction(108)).unwrap();
    mempool.lock().unwrap().add_transaction(transaction(109)).unwrap();
    let batch = scheduler
        .next_batch(true)
        .now_or_never()
        .expect("coalesced admissions must be observed after cancellation")
        .unwrap();
    assert_eq!(batch.transactions().len(), 2);
}
