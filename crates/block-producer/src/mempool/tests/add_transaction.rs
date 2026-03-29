use std::sync::Arc;

use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::block::BlockHeader;

use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{AddTransactionError, StateConflict};
use crate::mempool::Mempool;
use crate::test_utils::{MockProvenTxBuilder, mock_account_id};

#[test]
fn valid_with_state_from_multiple_parents() {
    let (mut uut, _) = Mempool::for_tests();

    let parent_a = MockProvenTxBuilder::with_account(
        mock_account_id(1),
        Word::empty(),
        Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .private_notes_created_range(0..1)
    .build();

    let parent_b = MockProvenTxBuilder::with_account(
        mock_account_id(2),
        Word::empty(),
        Word::new([300u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .private_notes_created_range(1..2)
    .build();

    let parent_c = MockProvenTxBuilder::with_account(
        mock_account_id(3),
        Word::empty(),
        Word::new([4500u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .private_notes_created_range(2..3)
    .build();

    let child = MockProvenTxBuilder::with_account(
        parent_a.account_id(),
        parent_a.account_update().final_state_commitment(),
        Word::new([4u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .unauthenticated_notes_range(0..3)
    .build();

    for tx in [parent_a, parent_b, parent_c, child] {
        let tx = AuthenticatedTransaction::from_inner(tx);
        let tx = Arc::new(tx);

        uut.add_transaction(tx).unwrap();
    }
}

/// Ensures that transactions that expire before or within the expiration slack of the chain tip
/// are rejected.
mod tx_expiration {
    use super::*;

    fn setup() -> Mempool {
        let (mut uut, _) = Mempool::for_tests();
        assert!(
            uut.config.expiration_slack > 0,
            "Test is only useful if there is some expiration slack"
        );

        // Create at least some locally retained state.
        let slack = uut.config.expiration_slack;
        for _ in 0..slack + 10 {
            let block = uut.select_block();
            let header = BlockHeader::mock(block.block_number, None, None, &[], Word::default());
            uut.commit_block(header);
        }

        uut
    }

    #[test]
    fn expiration_after_slack_limit_is_accepted() {
        let mut uut = setup();
        let limit = uut.chain_tip + uut.config.expiration_slack;

        let tx = MockProvenTxBuilder::with_account_index(0)
            .expiration_block_num(limit.child())
            .build();
        let tx = AuthenticatedTransaction::from_inner(tx).with_authentication_height(uut.chain_tip);
        let tx = Arc::new(tx);
        uut.add_transaction(tx).unwrap();
    }

    #[test]
    fn expiration_within_slack_limit_is_rejected() {
        let mut uut = setup();
        let limit = uut.chain_tip + uut.config.expiration_slack;

        for i in uut.chain_tip.child().as_u32()..=limit.as_u32() {
            let tx = MockProvenTxBuilder::with_account_index(0)
                .expiration_block_num(i.into())
                .build();
            let tx =
                AuthenticatedTransaction::from_inner(tx).with_authentication_height(uut.chain_tip);
            let tx = Arc::new(tx);
            let result = uut.add_transaction(tx);

            assert_matches!(
                result,
                Err(AddTransactionError::Expired { .. }),
                "Failed run with expiration {i} and limit {limit}"
            );
        }
    }

    #[test]
    fn already_expired_is_rejected() {
        let mut uut = setup();
        let tx = MockProvenTxBuilder::with_account_index(0)
            .expiration_block_num(uut.chain_tip)
            .build();
        let tx = AuthenticatedTransaction::from_inner(tx).with_authentication_height(uut.chain_tip);
        let tx = Arc::new(tx);
        let result = uut.add_transaction(tx);

        assert_matches!(result, Err(AddTransactionError::Expired { .. }));
    }
}

/// Ensures that a transaction's authentication height is always within the overlap between the
/// store chain tip and the locally retained state.
mod authentication_height {
    use super::*;

    fn setup() -> Mempool {
        let (mut uut, _) = Mempool::for_tests();
        assert!(
            uut.config.state_retention.get() > 0,
            "Test is only useful if there is some retained state"
        );

        // Create at least some locally retained state.
        let retention = uut.config.state_retention.get();
        for _ in 0..retention + 10 {
            let block = uut.select_block();
            let header = BlockHeader::mock(block.block_number, None, None, &[], Word::default());
            uut.commit_block(header);
        }

        uut
    }

    /// We expect a rejection if the tx was authenticated in some gap between the store and local
    /// state i.e. `oldest_local - 2`.
    #[test]
    fn stale_inputs_are_rejected() {
        let mut uut = setup();

        let oldest_local = uut.chain_tip.as_u32() - uut.config.state_retention.get() as u32 + 1;

        let tx = MockProvenTxBuilder::with_account_index(0).build();
        let tx = AuthenticatedTransaction::from_inner(tx)
            .with_authentication_height((oldest_local - 2).into());
        let tx = Arc::new(tx);
        uut.add_transaction(tx).unwrap_err();
    }

    /// Ensures that we guard against authentication height from lying about imaginary blocks beyond
    /// the chain tip. Since the authentication height is determined by the store, and this is
    /// considered internal, we panic as this is completely abnormal.
    #[test]
    #[should_panic]
    fn inputs_from_beyond_the_chain_tip_are_rejected() {
        let mut uut = setup();

        let tx = MockProvenTxBuilder::with_account_index(0).build();
        let tx = AuthenticatedTransaction::from_inner(tx)
            .with_authentication_height(uut.chain_tip.child());
        let tx = Arc::new(tx);
        let _ = uut.add_transaction(tx);
    }

    /// We expect transactions to be accepted in the `oldest-1..` range. We already test `>
    /// chain_tip` above. The `-1` is because we only require that there is _no gap_ between the
    /// authentication height and the local state, which would mean we are unable to authenticate
    /// against those blocks.
    #[test]
    fn inputs_from_within_overlap_are_accepted() {
        let mut uut = setup();

        let oldest_local = uut.chain_tip.as_u32() - uut.config.state_retention.get() as u32 + 1;

        for i in oldest_local - 1..=uut.chain_tip.as_u32() {
            let tx = MockProvenTxBuilder::with_account_index(i).build();
            let tx = AuthenticatedTransaction::from_inner(tx).with_authentication_height(i.into());
            let tx = Arc::new(tx);

            let result = uut.add_transaction(tx);

            assert_matches!(
                result,
                Ok(..),
                "Failed run with authentication height {i}, chain tip {} and oldest local {oldest_local}",
                uut.chain_tip
            );
        }
    }
}

#[test]
fn duplicate_nullifiers_are_rejected() {
    let (mut uut, _) = Mempool::for_tests();

    let tx_a = MockProvenTxBuilder::with_account(
        mock_account_id(111),
        Word::empty(),
        Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .nullifiers_range(1..11)
    .build();
    let tx_a = AuthenticatedTransaction::from_inner(tx_a);
    let tx_a = Arc::new(tx_a);

    let tx_b = MockProvenTxBuilder::with_account(
        mock_account_id(222),
        Word::empty(),
        Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .nullifiers_range(10..20)
    .build();
    let tx_b = AuthenticatedTransaction::from_inner(tx_b);
    let tx_b = Arc::new(tx_b);

    uut.add_transaction(tx_a).unwrap();
    let result = uut.add_transaction(tx_b);

    // We overlap with one nullifier.
    assert_matches!(
        result,
        Err(AddTransactionError::StateConflict(StateConflict::NullifiersAlreadyExist(..)))
    );
}

#[test]
fn duplicate_output_notes_are_rejected() {
    let (mut uut, _) = Mempool::for_tests();

    let tx_a = MockProvenTxBuilder::with_account(
        mock_account_id(111),
        Word::empty(),
        Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .private_notes_created_range(0..11)
    .build();
    let tx_a = AuthenticatedTransaction::from_inner(tx_a);
    let tx_a = Arc::new(tx_a);

    let tx_b = MockProvenTxBuilder::with_account(
        mock_account_id(222),
        Word::empty(),
        Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .private_notes_created_range(10..20)
    .build();
    let tx_b = AuthenticatedTransaction::from_inner(tx_b);
    let tx_b = Arc::new(tx_b);

    uut.add_transaction(tx_a).unwrap();
    let result = uut.add_transaction(tx_b);

    assert_matches!(
        result,
        Err(AddTransactionError::StateConflict(StateConflict::OutputNotesAlreadyExist(..)))
    );
}

#[test]
fn unknown_unauthenticated_notes_are_rejected() {
    let (mut uut, _) = Mempool::for_tests();

    let tx_a = MockProvenTxBuilder::with_account(
        mock_account_id(111),
        Word::empty(),
        Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .private_notes_created_range(0..11)
    .build();
    let tx_a = AuthenticatedTransaction::from_inner(tx_a);
    let tx_a = Arc::new(tx_a);

    let tx_b = MockProvenTxBuilder::with_account(
        mock_account_id(222),
        Word::empty(),
        Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
    )
    .unauthenticated_notes_range(0..12)
    .build();
    let tx_b = AuthenticatedTransaction::from_inner(tx_b);
    let tx_b = Arc::new(tx_b);

    uut.add_transaction(tx_a).unwrap();
    let result = uut.add_transaction(tx_b);

    assert_matches!(
        result,
        Err(AddTransactionError::StateConflict(StateConflict::UnauthenticatedNotesMissing(
            ..
        )))
    );
}

mod account_state {
    use super::*;

    #[test]
    fn matches_mempool_state() {
        let (mut uut, _) = Mempool::for_tests();

        let txs = MockProvenTxBuilder::sequential();
        for tx in txs {
            uut.add_transaction(tx).unwrap();
        }
    }

    #[test]
    fn matches_store_state() {
        let (mut uut, _) = Mempool::for_tests();

        let account_id = mock_account_id(123);

        let tx = MockProvenTxBuilder::with_account(
            account_id,
            Word::new([0u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
            Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
        )
        .build();
        let tx = AuthenticatedTransaction::from_inner(tx);
        let tx = Arc::new(tx);

        uut.add_transaction(tx).unwrap();
    }

    /// An inflight account state takes preference over the store's account state as the mempool's
    /// will also consider inflight transaction effects. This test ensures that this is the case.
    #[test]
    fn mempool_commitment_overrides_store() {
        let (mut uut, _) = Mempool::for_tests();

        let account_id = mock_account_id(123);

        let tx_a = MockProvenTxBuilder::with_account(
            account_id,
            Word::empty(),
            Word::new([0u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
        )
        .build();
        let tx_b = MockProvenTxBuilder::with_account(
            account_id,
            tx_a.account_update().final_state_commitment(),
            Word::new([10u32.into(), 11u32.into(), 12u32.into(), 13u32.into()]),
        )
        .build();
        let tx_a = AuthenticatedTransaction::from_inner(tx_a);
        let tx_b = AuthenticatedTransaction::from_inner(tx_b).with_store_state(Word::new([
            30u32.into(),
            31u32.into(),
            32u32.into(),
            33u32.into(),
        ]));

        let tx_a = Arc::new(tx_a);
        let tx_b = Arc::new(tx_b);

        uut.add_transaction(tx_a).unwrap();
        // We expect this to succeed because the local mempool account state will be correct, even
        // though the store's account state is a mismatch.
        uut.add_transaction(tx_b).unwrap();
    }

    #[test]
    fn mismatch_with_mempool_is_rejected() {
        let (mut uut, _) = Mempool::for_tests();

        let account_id = mock_account_id(123);

        let tx_a = MockProvenTxBuilder::with_account(
            account_id,
            Word::empty(),
            Word::new([0u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
        )
        .build();
        let tx_b = MockProvenTxBuilder::with_account(
            account_id,
            Word::new([10u32.into(), 11u32.into(), 12u32.into(), 13u32.into()]),
            Word::new([20u32.into(), 11u32.into(), 12u32.into(), 13u32.into()]),
        )
        .build();
        let tx_a = AuthenticatedTransaction::from_inner(tx_a);
        let tx_b = AuthenticatedTransaction::from_inner(tx_b);
        let tx_a = Arc::new(tx_a);
        let tx_b = Arc::new(tx_b);

        uut.add_transaction(tx_a).unwrap();
        let result = uut.add_transaction(tx_b);

        assert_matches!(
            result,
            Err(AddTransactionError::StateConflict(
                StateConflict::AccountCommitmentMismatch { .. }
            ))
        );
    }

    /// Ensures that store state is checked if there is no local mempool state.
    #[test]
    fn mismatch_with_store_is_rejected() {
        let (mut uut, _) = Mempool::for_tests();

        let account_id = mock_account_id(123);

        let tx = MockProvenTxBuilder::with_account(
            account_id,
            Word::new([0u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
            Word::new([3u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
        )
        .build();
        let tx = AuthenticatedTransaction::from_inner(tx).with_store_state(Word::new([
            6u32.into(),
            1u32.into(),
            2u32.into(),
            3u32.into(),
        ]));
        let tx = Arc::new(tx);

        let result = uut.add_transaction(tx);
        assert_matches!(
            result,
            Err(AddTransactionError::StateConflict(
                StateConflict::AccountCommitmentMismatch { .. }
            ))
        );
    }
}

mod new_account {
    use super::*;
    use crate::errors::StateConflict;

    #[test]
    fn is_valid() {
        let (mut uut, _) = Mempool::for_tests();

        let account_id = mock_account_id(123);

        let tx = MockProvenTxBuilder::with_account(
            account_id,
            Word::empty(),
            Word::new([0u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
        )
        .build();
        let tx = AuthenticatedTransaction::from_inner(tx);
        let tx = Arc::new(tx);
        uut.add_transaction(tx).unwrap();
    }

    #[test]
    fn already_exists_in_store() {
        let (mut uut, _) = Mempool::for_tests();

        let account_id = mock_account_id(123);

        let tx = MockProvenTxBuilder::with_account(
            account_id,
            Word::empty(),
            Word::new([0u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
        )
        .build();
        let tx = AuthenticatedTransaction::from_inner(tx).with_store_state(Word::new([
            5u32.into(),
            1u32.into(),
            2u32.into(),
            3u32.into(),
        ]));
        let tx = Arc::new(tx);
        let result = uut.add_transaction(tx);
        assert_matches!(
            result,
            Err(AddTransactionError::StateConflict(
                StateConflict::AccountCommitmentMismatch { .. }
            ))
        );
    }

    #[test]
    fn already_exists_in_mempool() {
        let (mut uut, _) = Mempool::for_tests();

        let account_id = mock_account_id(123);

        let tx = MockProvenTxBuilder::with_account(
            account_id,
            Word::empty(),
            Word::new([0u32.into(), 1u32.into(), 2u32.into(), 3u32.into()]),
        )
        .build();
        let tx = AuthenticatedTransaction::from_inner(tx);
        let tx = Arc::new(tx);

        uut.add_transaction(tx.clone()).unwrap();

        let result = uut.add_transaction(tx);
        assert_matches!(
            result,
            Err(AddTransactionError::StateConflict(
                StateConflict::AccountCommitmentMismatch { .. }
            ))
        );
    }
}
