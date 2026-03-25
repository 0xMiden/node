use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::block::{BlockHeader, BlockNumber};
use pretty_assertions::assert_eq;
use serial_test::serial;

use super::*;
use crate::test_utils::MockProvenTxBuilder;
use crate::test_utils::batch::TransactionBatchConstructor;

mod add_transaction;

impl Mempool {
    /// Returns an empty [`Mempool`] and a perfect clone intended for use as the Unit Under Test and
    /// the reference instance.
    ///
    /// The clone is important as this guarantees that the internal _hash_ state is the same. This
    /// is relevant for internal `HashMap`s which would otherwise give different iteration order
    /// which in turn doesn't let different mempool instances give the same results.
    fn for_tests() -> (Self, Self) {
        let uut = Self::new(
            BlockNumber::GENESIS,
            MempoolConfig {
                expiration_slack: 3,
                state_retention: NonZeroUsize::new(5).unwrap(),
                ..Default::default()
            },
        );

        (uut.clone(), uut)
    }
}

// OTEL TRACE TESTS
// ================================================================================================

#[tokio::test]
#[serial(open_telemetry_tracing)]
async fn add_transaction_traces_are_correct() {
    let (mut rx_export, _rx_shutdown) = miden_node_utils::logging::setup_test_tracing().unwrap();

    let (mut uut, _) = Mempool::for_tests();
    let txs = MockProvenTxBuilder::sequential();
    uut.add_transaction(txs[0].clone()).unwrap();

    let mut found_span = None;
    for _ in 0..500 {
        if let Ok(span_data) = tokio::time::timeout(Duration::from_secs(1), rx_export.recv()).await {
            let span_data = span_data.unwrap();
            if span_data.name.as_ref() == "COMPONENT.add_transaction" {
                found_span = Some(span_data);
                break;
            }
        }
    }

    assert_matches!(&found_span, Some(span_data) if span_data.name.as_ref() == "COMPONENT.add_transaction");
    let Some(span_data) = found_span else {
        unreachable!();
    };
    assert!(span_data.attributes.iter().any(|kv| kv.key == "code.module.name".into()
        && kv.value == "miden_node_block_producer::mempool".into()));

}

// BATCH FAILED TESTS
// ================================================================================================

#[test]
fn children_of_failed_batches_are_ignored() {
    // Batches are proved concurrently. This makes it possible for a child job to complete after
    // the parent has been reverted (and therefore reverting the child job). Such a child job
    // should be ignored.
    let txs = MockProvenTxBuilder::sequential();

    let (mut uut, _) = Mempool::for_tests();
    uut.add_transaction(txs[0].clone()).unwrap();
    let parent_batch = uut.select_batch().unwrap();
    assert_eq!(parent_batch.txs(), vec![txs[0].clone()]);

    uut.add_transaction(txs[1].clone()).unwrap();
    let child_batch_a = uut.select_batch().unwrap();
    assert_eq!(child_batch_a.txs(), vec![txs[1].clone()]);

    uut.add_transaction(txs[2].clone()).unwrap();
    let next_batch = uut.select_batch().unwrap();
    assert_eq!(next_batch.txs(), vec![txs[2].clone()]);

    // Child batch jobs are now dangling.
    uut.rollback_batch(parent_batch.id());
    let reference = uut.clone();

    // Success or failure of the child job should effectively do nothing.
    uut.rollback_batch(child_batch_a.id());
    assert_eq!(uut, reference);

    let proven_batch =
        Arc::new(ProvenBatch::mocked_from_transactions([txs[2].raw_proven_transaction()]));
    uut.commit_batch(proven_batch);
    assert_eq!(uut, reference);
}

#[test]
fn failed_batch_transactions_are_requeued() {
    let txs = MockProvenTxBuilder::sequential();

    let (mut uut, mut reference) = Mempool::for_tests();
    uut.add_transaction(txs[0].clone()).unwrap();
    uut.select_batch().unwrap();

    uut.add_transaction(txs[1].clone()).unwrap();
    let failed_batch = uut.select_batch().unwrap();

    uut.add_transaction(txs[2].clone()).unwrap();
    uut.select_batch().unwrap();

    // Middle batch failed, so it and its child transaction should be re-entered into the queue.
    uut.rollback_batch(failed_batch.id());

    reference.add_transaction(txs[0].clone()).unwrap();
    reference.select_batch().unwrap();
    reference.add_transaction(txs[1].clone()).unwrap();
    reference.add_transaction(txs[2].clone()).unwrap();

    assert_eq!(uut, reference);
}

// BLOCK COMMITTED TESTS
// ================================================================================================

/// Expired transactions should be reverted once their expiration block is committed.
#[test]
fn block_commit_reverts_expired_txns() {
    let (mut uut, _) = Mempool::for_tests();
    uut.config.expiration_slack = 0;

    let tx_to_commit = MockProvenTxBuilder::with_account_index(0).build();
    let tx_to_commit = Arc::new(AuthenticatedTransaction::from_inner(tx_to_commit));

    // Force the tx into a pending block.
    uut.add_transaction(tx_to_commit.clone()).unwrap();
    uut.select_batch().unwrap();
    uut.commit_batch(Arc::new(ProvenBatch::mocked_from_transactions([
        tx_to_commit.raw_proven_transaction()
    ])));
    let (block, _) = uut.select_block();
    // A reverted transaction behaves as if it never existed, the current state is the expected
    // outcome, plus an extra committed block at the end.
    let mut reference = uut.clone();

    // Add a new transaction which will expire when the pending block is committed.
    let tx_to_revert =
        MockProvenTxBuilder::with_account_index(1).expiration_block_num(block).build();
    let tx_to_revert = Arc::new(AuthenticatedTransaction::from_inner(tx_to_revert));
    uut.add_transaction(tx_to_revert).unwrap();

    // Commit the pending block which should revert the above tx.
    let arb_header = BlockHeader::mock(block, None, None, &[], Word::empty());
    uut.commit_block(arb_header.clone());
    reference.commit_block(arb_header);

    assert_eq!(uut, reference);
}

#[test]
fn empty_block_commitment() {
    let (mut uut, _) = Mempool::for_tests();

    for _ in 0..3 {
        let (number, _) = uut.select_block();
        let arb_header = BlockHeader::mock(number, None, None, &[], Word::empty());
        uut.commit_block(arb_header);
    }
}

#[test]
#[should_panic]
fn block_commitment_is_rejected_if_no_block_is_in_flight() {
    let arb_header = BlockHeader::mock(0, None, None, &[], Word::empty());
    Mempool::for_tests().0.commit_block(arb_header);
}

#[test]
#[should_panic]
fn cannot_have_multiple_inflight_blocks() {
    let (mut uut, _) = Mempool::for_tests();

    uut.select_block();
    uut.select_block();
}

// BLOCK FAILED TESTS
// ================================================================================================

/// A failed block should have all of its transactions reverted.
#[test]
fn block_failure_reverts_its_transactions() {
    // We will revert everything so the reference should be the empty mempool.
    let (mut uut, reference) = Mempool::for_tests();

    let reverted_txs = MockProvenTxBuilder::sequential();

    uut.add_transaction(reverted_txs[0].clone()).unwrap();
    uut.select_batch().unwrap();
    uut.commit_batch(Arc::new(ProvenBatch::mocked_from_transactions([
        reverted_txs[0].raw_proven_transaction()
    ])));

    // Block 1 will contain just the first batch.
    let (number, _batches) = uut.select_block();

    // Create another dependent batch.
    uut.add_transaction(reverted_txs[1].clone()).unwrap();
    uut.select_batch();
    // Create another dependent transaction.
    uut.add_transaction(reverted_txs[2].clone()).unwrap();

    // Fail the block which should result in everything reverting.
    uut.rollback_block(number);

    assert_eq!(uut, reference);
}

/// Ensures that reverting a subtree removes the node and all its descendents. We test this by
/// comparing against a reference mempool that never had the subtree inserted at all.
#[test]
fn subtree_reversion_removes_all_descendents() {
    let (mut uut, mut reference) = Mempool::for_tests();

    let reverted_txs = MockProvenTxBuilder::sequential();

    uut.add_transaction(reverted_txs[0].clone()).unwrap();
    uut.select_batch().unwrap();

    uut.add_transaction(reverted_txs[1].clone()).unwrap();
    let to_revert = uut.select_batch().unwrap();

    uut.add_transaction(reverted_txs[2].clone()).unwrap();
    uut.revert_subtree(NodeId::ProposedBatch(to_revert.id()));

    // We expect the second batch and the latter reverted txns to be non-existent.
    reference.add_transaction(reverted_txs[0].clone()).unwrap();
    reference.select_batch().unwrap();

    assert_eq!(uut, reference);
}

/// We've decided that transactions from a rolled back batch should be requeued.
///
/// This test checks this at a basic level by ensuring that rolling back a batch is the same as
/// never selecting that batch i.e. that the set of unbatched transactions remains the same.
#[test]
fn transactions_from_reverted_batches_are_requeued() {
    let (mut uut, mut reference) = Mempool::for_tests();

    let tx_set_a = MockProvenTxBuilder::sequential();
    let tx_set_b = MockProvenTxBuilder::sequential();

    uut.add_transaction(tx_set_b[0].clone()).unwrap();
    uut.add_transaction(tx_set_a[0].clone()).unwrap();
    uut.select_batch().unwrap();

    uut.add_transaction(tx_set_b[1].clone()).unwrap();
    uut.add_transaction(tx_set_a[1].clone()).unwrap();
    let batch = uut.select_batch().unwrap();

    uut.add_transaction(tx_set_b[2].clone()).unwrap();
    uut.add_transaction(tx_set_a[2].clone()).unwrap();
    uut.rollback_batch(batch.id());

    reference.add_transaction(tx_set_b[0].clone()).unwrap();
    reference.add_transaction(tx_set_a[0].clone()).unwrap();
    reference.select_batch().unwrap();
    reference.add_transaction(tx_set_b[1].clone()).unwrap();
    reference.add_transaction(tx_set_a[1].clone()).unwrap();
    reference.add_transaction(tx_set_b[2].clone()).unwrap();
    reference.add_transaction(tx_set_a[2].clone()).unwrap();

    assert_eq!(uut, reference);
}

/// This test checks that pass through transactions can successfully be added to an empty mempool,
/// and that they work as expected.
#[test]
fn pass_through_txs_on_an_empty_account() {
    let (mut uut, _) = Mempool::for_tests();

    let tx_final = MockProvenTxBuilder::with_account_index(0).build();
    let tx_final = Arc::new(AuthenticatedTransaction::from_inner(tx_final));

    let account_update = tx_final.account_update().clone();
    let tx_pass_through_base = MockProvenTxBuilder::with_account(
        account_update.account_id(),
        account_update.initial_state_commitment(),
        account_update.initial_state_commitment(),
    );

    // Note: transactions _must_ have an input note or update an account to be considered valid.
    // Since by definition pass through txs don't update an account, they must have a nullifier.
    let tx_pass_through_a = tx_pass_through_base.clone().nullifiers_range(0..2).build();
    let tx_pass_through_a = Arc::new(AuthenticatedTransaction::from_inner(tx_pass_through_a));

    let tx_pass_through_b = tx_pass_through_base.nullifiers_range(3..5).build();
    let tx_pass_through_b = Arc::new(AuthenticatedTransaction::from_inner(tx_pass_through_b));

    uut.add_transaction(tx_pass_through_a.clone()).unwrap();
    uut.add_transaction(tx_pass_through_b.clone()).unwrap();
    uut.add_transaction(tx_final.clone()).unwrap();

    let batch = uut.select_batch().unwrap();

    // Ensure the batch correctly aggregates the account update.
    let expected = std::iter::once((
        account_update.account_id(),
        account_update.initial_state_commitment(),
        account_update.final_state_commitment(),
    ));
    itertools::assert_equal(batch.account_updates(), expected);

    // Ensure the batch contains a,b and final. Final should also be the last tx since its order
    // is required.
    assert!(batch.txs().contains(&tx_pass_through_a));
    assert!(batch.txs().contains(&tx_pass_through_b));
    assert_eq!(batch.txs().last().unwrap(), &tx_final);
}

/// Tests that pass through transactions retain parent-child relations based on notes, even though
/// they act as "siblings" for account purposes.
#[test]
fn pass_through_txs_with_note_dependencies() {
    let (mut uut, mut reference) = Mempool::for_tests();

    // Used to get a valid account ID.
    let tx_final = MockProvenTxBuilder::with_account_index(0).build();
    let account_update = tx_final.account_update();

    let tx_pass_through_base = MockProvenTxBuilder::with_account(
        account_update.account_id(),
        account_update.initial_state_commitment(),
        account_update.initial_state_commitment(),
    );

    // Note: transactions _must_ have an input note or update an account to be considered valid.
    // Since by definition pass through txs don't update an account, they must have a nullifier.
    let tx_pass_through_a = tx_pass_through_base
        .clone()
        .nullifiers_range(0..2)
        .private_notes_created_range(3..4)
        .build();
    let tx_pass_through_a = Arc::new(AuthenticatedTransaction::from_inner(tx_pass_through_a));

    // This includes a note (3) created by (a).
    let tx_pass_through_b = tx_pass_through_base.unauthenticated_notes_range(3..4).build();
    let tx_pass_through_b = Arc::new(AuthenticatedTransaction::from_inner(tx_pass_through_b));

    // Select batches such that (a) and (b) go into separate batches.
    //
    // We then rollback batch (a) and check that batch (b) is also reverted which tests that the
    // relationship was correctly inferred by the mempool.
    uut.add_transaction(tx_pass_through_a.clone()).unwrap();
    let batch_a = uut.select_batch().unwrap();
    assert_eq!(batch_a.txs(), std::slice::from_ref(&tx_pass_through_a));

    uut.add_transaction(tx_pass_through_b.clone()).unwrap();
    let batch_b = uut.select_batch().unwrap();
    assert_eq!(batch_b.txs(), std::slice::from_ref(&tx_pass_through_b));

    // Rollback (a) and check that (b) also reverted by comparing to the reference.
    uut.rollback_batch(batch_a.id());
    reference.add_transaction(tx_pass_through_a).unwrap();
    reference.add_transaction(tx_pass_through_b).unwrap();

    assert_eq!(uut, reference);
}
