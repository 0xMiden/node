use std::num::NonZeroUsize;
use std::sync::Arc;

use assert_matches::assert_matches;
use miden_node_proto::domain::sequencer::AuthenticatedTransaction;
use miden_protocol::batch::BatchId;
use miden_protocol::block::BlockNumber;
use pretty_assertions::assert_eq;

use crate::domain::batch::BatchParameters;
use crate::errors::{MempoolSubmissionError, StateConflict};
use crate::mempool::Mempool;
use crate::test_utils::{MockAuthenticatedTxBuilder, MockProvenTxBuilder};

/// This checks that transactions from a user batch remain as the same batch upon selection.
///
/// Since the selection process is random, its difficult to test this directly, but this at
/// least acts as a smoke test. We select two batches and check that one of them is the user
/// batch.
#[test]
fn user_batch_is_isolated_from_other_transactions() {
    let (mut uut, _) = Mempool::for_tests();

    let conventional_a = build_tx(MockProvenTxBuilder::with_account_index(200));
    let conventional_b = build_tx(MockProvenTxBuilder::with_account_index(201));

    uut.add_transaction(conventional_a.clone()).unwrap();
    uut.add_transaction(conventional_b.clone()).unwrap();

    let user_batch_txs = MockProvenTxBuilder::sequential();
    let user_batch_id =
        BatchId::from_transactions(user_batch_txs.iter().map(|tx| tx.raw_proven_transaction()));
    let user_parameters = BatchParameters { reference_block: 42.into() };
    uut.add_user_batch(&user_batch_txs, user_parameters).unwrap();

    let batch_a = uut.select_any_batch().unwrap();
    let batch_b = uut.select_any_batch().unwrap();

    let (user, conventional) = if batch_a.id() == user_batch_id {
        (batch_a, batch_b)
    } else {
        (batch_b, batch_a)
    };

    assert_eq!(user.id(), user_batch_id);
    assert_eq!(user.transactions(), user_batch_txs.as_slice());
    assert_eq!(user.parameters(), user_parameters);

    assert_eq!(conventional.transactions().len(), 2);
    assert!(conventional.transactions().contains(&conventional_a));
    assert!(conventional.transactions().contains(&conventional_b));
    assert_eq!(
        conventional.parameters(),
        BatchParameters { reference_block: BlockNumber::GENESIS }
    );
}

#[test]
fn user_batch_respects_batch_budget() {
    let (mut uut, _) = Mempool::for_tests();
    uut.config.batch_budget.transactions = 1;

    let user_batch_txs = MockProvenTxBuilder::sequential();
    let result = uut.add_user_batch(&user_batch_txs[..2], BatchParameters::for_tests());

    assert_matches!(result, Err(MempoolSubmissionError::CapacityExceeded));
}

#[test]
fn user_batch_capacity_counts_batched_uncommitted_transactions() {
    let (mut uut, _) = Mempool::for_tests();
    uut.config.tx_capacity = NonZeroUsize::new(1).unwrap();
    let conventional = build_tx(MockProvenTxBuilder::with_account_index(300));
    let user_batch = [build_tx(MockProvenTxBuilder::with_account_index(301))];

    uut.add_transaction(conventional).unwrap();
    uut.select_any_batch().unwrap();

    assert_matches!(
        uut.add_user_batch(&user_batch, BatchParameters::for_tests()),
        Err(MempoolSubmissionError::CapacityExceeded)
    );
}

#[test]
fn user_batch_counts_as_full_batch() {
    let (mut uut, _) = Mempool::for_tests();
    uut.config.batch_budget.transactions = 3;

    let user_batch_txs = MockProvenTxBuilder::sequential();
    uut.add_user_batch(&user_batch_txs[..1], BatchParameters::for_tests()).unwrap();

    let batch = uut.select_full_batch().unwrap();
    assert_eq!(batch.transactions(), &user_batch_txs[..1]);
}

#[test]
fn user_batch_with_internal_state_conflicts_are_rejected() {
    let (mut uut, reference) = Mempool::for_tests();

    let conflicting_a = tx_with_nullifiers(10, 0..1);
    let conflicting_b = tx_with_nullifiers(11, 0..1);

    let result = uut.add_user_batch(
        &[conflicting_a.clone(), conflicting_b.clone()],
        BatchParameters::for_tests(),
    );

    assert_matches!(
        result,
        Err(MempoolSubmissionError::StateConflict(StateConflict::NullifiersAlreadyExist(..)))
    );

    assert_eq!(uut, reference);
}

#[test]
fn user_batch_conflicts_with_existing_state_are_rejected() {
    let (mut uut, mut reference) = Mempool::for_tests();

    let existing = tx_with_nullifiers(20, 5..6);
    uut.add_transaction(existing.clone()).unwrap();
    reference.add_transaction(existing.clone()).unwrap();

    let conflicting = tx_with_nullifiers(21, 5..6);
    let companion = tx_with_nullifiers(22, 6..7);

    let result =
        uut.add_user_batch(&[conflicting.clone(), companion.clone()], BatchParameters::for_tests());

    assert_matches!(
        result,
        Err(MempoolSubmissionError::StateConflict(StateConflict::NullifiersAlreadyExist(..)))
    );

    assert_eq!(uut, reference);
}

fn build_tx(builder: MockProvenTxBuilder) -> Arc<AuthenticatedTransaction> {
    Arc::new(MockAuthenticatedTxBuilder::new(builder.build()).build())
}

fn tx_with_nullifiers(
    account_index: u32,
    range: std::ops::Range<u64>,
) -> Arc<AuthenticatedTransaction> {
    build_tx(MockProvenTxBuilder::with_account_index(account_index).nullifiers_range(range))
}
