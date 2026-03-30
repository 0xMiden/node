use std::sync::Arc;

use assert_matches::assert_matches;
use miden_protocol::batch::BatchId;
use pretty_assertions::assert_eq;

use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{MempoolSubmissionError, StateConflict};
use crate::mempool::Mempool;
use crate::test_utils::MockProvenTxBuilder;

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
    uut.add_user_batch(&user_batch_txs).unwrap();

    let batch_a = uut.select_batch().unwrap();
    let batch_b = uut.select_batch().unwrap();

    let (user, conventional) = if batch_a.id() == user_batch_id {
        (batch_a, batch_b)
    } else {
        (batch_b, batch_a)
    };

    assert_eq!(user.id(), user_batch_id);
    assert_eq!(user.transactions(), user_batch_txs.as_slice());

    assert_eq!(conventional.transactions().len(), 2);
    assert!(conventional.transactions().contains(&conventional_a));
    assert!(conventional.transactions().contains(&conventional_b));
}

#[test]
fn user_batch_respects_batch_budget() {
    let (mut uut, _) = Mempool::for_tests();
    uut.config.batch_budget.transactions = 1;

    let user_batch_txs = MockProvenTxBuilder::sequential();
    let result = uut.add_user_batch(&user_batch_txs[..2]);

    assert_matches!(result, Err(MempoolSubmissionError::CapacityExceeded));
}

#[test]
fn user_batch_with_internal_state_conflicts_are_rejected() {
    let (mut uut, reference) = Mempool::for_tests();

    let conflicting_a = tx_with_nullifiers(10, 0..1);
    let conflicting_b = tx_with_nullifiers(11, 0..1);

    let result = uut.add_user_batch(&[conflicting_a.clone(), conflicting_b.clone()]);

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

    let result = uut.add_user_batch(&[conflicting.clone(), companion.clone()]);

    assert_matches!(
        result,
        Err(MempoolSubmissionError::StateConflict(StateConflict::NullifiersAlreadyExist(..)))
    );

    assert_eq!(uut, reference);
}

fn build_tx(builder: MockProvenTxBuilder) -> Arc<AuthenticatedTransaction> {
    Arc::new(AuthenticatedTransaction::from_inner(builder.build()))
}

fn tx_with_nullifiers(
    account_index: u32,
    range: std::ops::Range<u64>,
) -> Arc<AuthenticatedTransaction> {
    build_tx(MockProvenTxBuilder::with_account_index(account_index).nullifiers_range(range))
}
