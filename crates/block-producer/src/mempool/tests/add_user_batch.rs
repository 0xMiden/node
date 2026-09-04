use std::num::NonZeroUsize;
use std::sync::Arc;

use assert_matches::assert_matches;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::BlockNumber;
use pretty_assertions::assert_eq;

use crate::domain::batch::BatchParameters;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{MempoolSubmissionError, StateConflict};
use crate::mempool::Mempool;
use crate::test_utils::MockProvenTxBuilder;
use crate::test_utils::batch::TransactionBatchConstructor;

#[test]
fn user_batch_bypasses_batch_proving() {
    let (mut uut, _) = Mempool::for_tests();

    let conventional_a = build_tx(MockProvenTxBuilder::with_account_index(200));
    let conventional_b = build_tx(MockProvenTxBuilder::with_account_index(201));

    uut.add_transaction(conventional_a.clone()).unwrap();
    uut.add_transaction(conventional_b.clone()).unwrap();

    let user_batch_txs = MockProvenTxBuilder::sequential();
    let user_batch_id =
        BatchId::from_transactions(user_batch_txs.iter().map(|tx| tx.raw_proven_transaction()));
    let user_proof = Arc::new(ProvenBatch::mocked_from_transactions(
        user_batch_txs.iter().map(|tx| tx.raw_proven_transaction()),
    ));
    let user_parameters = BatchParameters { reference_block: 42.into() };
    uut.add_user_batch(&user_batch_txs, user_parameters, Arc::clone(&user_proof))
        .unwrap();

    let conventional = uut.select_any_batch().unwrap();
    assert_eq!(conventional.transactions().len(), 2);
    assert!(conventional.transactions().contains(&conventional_a));
    assert!(conventional.transactions().contains(&conventional_b));
    assert_eq!(
        conventional.parameters(),
        BatchParameters { reference_block: BlockNumber::GENESIS }
    );

    assert_eq!(user_proof.id(), user_batch_id);
    let block = uut.select_block();
    assert_eq!(block.batches, vec![user_proof]);
}

#[test]
fn user_batch_respects_batch_budget() {
    let (mut uut, _) = Mempool::for_tests();
    uut.config.batch_budget.transactions = 1;

    let user_batch_txs = MockProvenTxBuilder::sequential();
    let result = add_user_batch(&mut uut, &user_batch_txs[..2], BatchParameters::for_tests());

    assert_matches!(result, Err(MempoolSubmissionError::CapacityExceeded));
}

#[test]
fn user_batch_rejects_a_mismatched_proof() {
    let (mut uut, reference) = Mempool::for_tests();
    let [batch_tx, proof_tx] = [
        build_tx(MockProvenTxBuilder::with_account_index(40)),
        build_tx(MockProvenTxBuilder::with_account_index(41)),
    ];
    let proof = ProvenBatch::mocked_from_transactions([proof_tx.raw_proven_transaction()]);

    let result = uut.add_user_batch(&[batch_tx], BatchParameters::for_tests(), Arc::new(proof));

    assert_matches!(result, Err(MempoolSubmissionError::BatchIdMismatch { .. }));
    assert_eq!(uut, reference);
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
        add_user_batch(&mut uut, &user_batch, BatchParameters::for_tests()),
        Err(MempoolSubmissionError::CapacityExceeded)
    );
}

#[test]
fn user_batch_is_not_selected_for_proving() {
    let (mut uut, _) = Mempool::for_tests();
    uut.config.batch_budget.transactions = 3;

    let user_batch_txs = MockProvenTxBuilder::sequential();
    add_user_batch(&mut uut, &user_batch_txs[..1], BatchParameters::for_tests()).unwrap();

    assert!(uut.select_any_batch().is_none());
    assert!(uut.select_full_batch().is_none());
    assert_eq!(uut.select_block().batches.len(), 1);
}

#[test]
fn user_batch_with_internal_state_conflicts_are_rejected() {
    let (mut uut, reference) = Mempool::for_tests();

    let conflicting_a = tx_with_nullifiers(10, 0..1);
    let conflicting_b = tx_with_nullifiers(11, 0..1);

    let result = add_user_batch(
        &mut uut,
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

    let result = add_user_batch(
        &mut uut,
        &[conflicting.clone(), companion.clone()],
        BatchParameters::for_tests(),
    );

    assert_matches!(
        result,
        Err(MempoolSubmissionError::StateConflict(StateConflict::NullifiersAlreadyExist(..)))
    );

    assert_eq!(uut, reference);
}

fn build_tx(builder: MockProvenTxBuilder) -> Arc<AuthenticatedTransaction> {
    Arc::new(AuthenticatedTransaction::from_inner(builder.build()))
}

fn add_user_batch(
    mempool: &mut Mempool,
    txs: &[Arc<AuthenticatedTransaction>],
    parameters: BatchParameters,
) -> Result<BlockNumber, MempoolSubmissionError> {
    let proof =
        ProvenBatch::mocked_from_transactions(txs.iter().map(|tx| tx.raw_proven_transaction()));
    mempool.add_user_batch(txs, parameters, Arc::new(proof))
}

fn tx_with_nullifiers(
    account_index: u32,
    range: std::ops::Range<u64>,
) -> Arc<AuthenticatedTransaction> {
    build_tx(MockProvenTxBuilder::with_account_index(account_index).nullifiers_range(range))
}
