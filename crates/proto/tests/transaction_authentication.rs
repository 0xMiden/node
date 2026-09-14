use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;

use miden_node_proto::domain::sequencer::{
    AuthenticatedTransaction,
    TransactionAuthenticationError,
    TransactionInputs,
};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountId,
    AccountIdVersion,
    AccountType,
    AccountUpdateDetails,
    AssetCallbackFlag,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OutputNote, ProvenTransaction, TxAccountUpdate};

fn account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

fn transaction_and_inputs() -> (Arc<ProvenTransaction>, TransactionInputs) {
    let account_update = TxAccountUpdate::new(
        account_id(1),
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();
    let nullifiers = [
        Nullifier::from_raw(Word::from([1u32, 0, 0, 0])),
        Nullifier::from_raw(Word::from([2u32, 0, 0, 0])),
    ];
    let tx = ProvenTransaction::new(
        account_update,
        nullifiers,
        Vec::<OutputNote>::new(),
        BlockNumber::GENESIS,
        Word::empty(),
        BlockNumber::from(100),
        miden_protocol::testing::dummy_execution_proof(),
    )
    .unwrap();
    let inputs = TransactionInputs {
        account_id: tx.account_id(),
        account_commitment: Some(tx.account_update().initial_state_commitment()),
        nullifiers: nullifiers.into_iter().map(|nullifier| (nullifier, None)).collect(),
        found_unauthenticated_notes: HashSet::new(),
        current_block_height: BlockNumber::from(10),
    };
    (Arc::new(tx), inputs)
}

#[test]
fn authentication_rejects_missing_nullifier_results() {
    let (tx, mut inputs) = transaction_and_inputs();
    inputs.nullifiers.clear();
    assert_eq!(
        AuthenticatedTransaction::new_unchecked(Arc::clone(&tx), inputs).unwrap_err(),
        TransactionAuthenticationError::MissingNullifiers(tx.nullifiers().collect()),
    );

    for substitute_unrelated_nullifier in [false, true] {
        let (tx, mut inputs) = transaction_and_inputs();
        let missing_nullifier = tx.nullifiers().next().unwrap();
        inputs.nullifiers.remove(&missing_nullifier);
        if substitute_unrelated_nullifier {
            inputs.nullifiers.insert(Nullifier::from_raw(Word::from([3u32, 0, 0, 0])), None);
        }
        assert_eq!(
            AuthenticatedTransaction::new_unchecked(tx, inputs).unwrap_err(),
            TransactionAuthenticationError::MissingNullifiers(vec![missing_nullifier]),
        );
    }
}

#[test]
fn authentication_rejects_inputs_for_another_account() {
    let (tx, mut inputs) = transaction_and_inputs();
    inputs.account_id = account_id(2);
    let expected = tx.account_id();
    let actual = inputs.account_id;
    assert_eq!(
        AuthenticatedTransaction::new_unchecked(tx, inputs).unwrap_err(),
        TransactionAuthenticationError::AccountIdMismatch { expected, actual },
    );
}

#[test]
fn authentication_rejects_spent_nullifiers() {
    let (tx, mut inputs) = transaction_and_inputs();
    let nullifiers: Vec<_> = tx.nullifiers().collect();
    for nullifier in &nullifiers {
        inputs.nullifiers.insert(*nullifier, NonZeroU32::new(5));
    }
    assert_eq!(
        AuthenticatedTransaction::new_unchecked(tx, inputs).unwrap_err(),
        TransactionAuthenticationError::NullifiersAlreadyExist(nullifiers),
    );
}

#[test]
fn authentication_accepts_complete_unspent_inputs_with_pending_account_dependencies() {
    let (tx, mut inputs) = transaction_and_inputs();
    let store_account_state = Some(Word::from([9u32, 10, 11, 12]));
    inputs.account_commitment = store_account_state;
    let authentication_height = inputs.current_block_height;
    let authenticated = AuthenticatedTransaction::new_unchecked(Arc::clone(&tx), inputs).unwrap();

    assert_eq!(authenticated.proven_transaction(), tx);
    assert_eq!(authenticated.store_account_state(), store_account_state);
    assert_eq!(authenticated.authentication_height(), authentication_height);
}
