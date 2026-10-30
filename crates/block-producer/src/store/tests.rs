use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;

use miden_node_store::{BlockWriter, DatabaseError, GenesisState, State, WriterTask};
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountType, AccountUpdateDetails, AssetCallbackFlag};
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNumber,
    BlockSignatures,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::account_id;
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_protocol::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
    OutputNote,
    PrivateOutputNote,
    TransactionHeader,
};

use super::get_tx_inputs;
use crate::errors::{MempoolSubmissionError, StateConflict};
use crate::test_utils::MockProvenTxBuilder;

async fn fixture() -> (tempfile::TempDir, Arc<State>, BlockWriter, WriterTask) {
    let directory = tempfile::tempdir().unwrap();
    let key = random_secret_key();
    let genesis = GenesisState::new(
        vec![],
        test_fee_params(),
        1,
        ValidatorConfig::new(vec![key.public_key()], 1).unwrap(),
        test_protocol_config(),
    )
    .into_block()
    .unwrap();
    State::bootstrap(genesis, directory.path()).await.unwrap();
    let (state, writer, _proof_writer, task) =
        State::load(directory.path(), miden_node_utils::clap::StorageOptions::default())
            .await
            .unwrap()
            .start(miden_node_utils::shutdown::CancellationToken::new());
    (directory, state, writer, task)
}

/// Builds the first block with a private account, a committed note, and a spent nullifier.
async fn first_block(state: &State, id: AccountId, commitment: Word, note: Note) -> SignedBlock {
    state
        .read(move |view| -> Result<_, DatabaseError> {
            let parent = view.tx.select_block_header(BlockNumber::GENESIS)?.unwrap();
            let accounts = AccountTree::with_entries([(id, commitment)]).unwrap();
            let nullifiers = NullifierTree::with_entries([(note.nullifier(), 1.into())]).unwrap();
            let transaction = TransactionHeader::new(
                id,
                Word::empty(),
                commitment,
                InputNotes::new_unchecked(vec![note.nullifier().into()]),
                vec![*note.header()],
            )
            .unwrap();
            let body = BlockBody::new(
                vec![
                    BlockAccountUpdate::new(id, commitment, AccountUpdateDetails::Private).unwrap(),
                ],
                vec![vec![(
                    0,
                    OutputNote::Private(
                        PrivateOutputNote::new(*note.header(), note.attachments().clone()).unwrap(),
                    ),
                )]],
                nullifiers.entries().map(|(nullifier, _)| nullifier).collect(),
                OrderedTransactionHeaders::new_unchecked(vec![transaction]),
            )
            .unwrap();
            let header = BlockHeader::new(
                parent.commitment(),
                1.into(),
                view.snapshot.blockchain.commitment(),
                accounts.root(),
                nullifiers.root(),
                body.compute_block_note_tree().root(),
                body.transaction_commitment(),
                parent.validator_config().clone(),
                parent.fee_parameters().clone(),
                parent.protocol_config_commitment(),
                None,
                parent.timestamp() + 1,
            );
            Ok(SignedBlock::new_unchecked(header, body, BlockSignatures::new(vec![]).unwrap()))
        })
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn reads_transaction_inputs_before_and_after_a_block_commit() {
    let (_directory, state, mut writer, task) = fixture().await;
    let tx = MockProvenTxBuilder::with_account_index(100)
        .unauthenticated_notes_range(1..3)
        .build();
    let note = Note::mock_noop(Word::from([0, 0, 0, 1u32]));
    let spent = note.nullifier();
    let expected_note = note.id();
    let commitment = Word::from([1u32, 2, 3, 4]);
    let block = first_block(&state, tx.account_id(), commitment, note).await;

    let inputs = get_tx_inputs(&state, &tx).await.unwrap();
    assert_eq!(inputs.account_commitment, None);
    assert!(inputs.nullifiers.values().all(Option::is_none));
    assert!(inputs.found_unauthenticated_notes.is_empty());
    assert_eq!(inputs.current_block_height, BlockNumber::GENESIS);

    let id = tx.account_id();
    writer.apply_block(block, None).await.unwrap();

    let inputs = get_tx_inputs(&state, &tx).await.unwrap();
    assert_eq!(inputs.account_id, id);
    assert_eq!(inputs.account_commitment, Some(commitment));
    assert_eq!(inputs.nullifiers[&spent], NonZeroU32::new(1));
    assert_eq!(inputs.nullifiers.len(), 2);
    assert_eq!(inputs.nullifiers.values().filter(|height| height.is_none()).count(), 1);
    assert_eq!(inputs.found_unauthenticated_notes, HashSet::from([expected_note]));
    assert_eq!(inputs.current_block_height, BlockNumber::from(1));
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_a_new_account_with_an_existing_prefix() {
    let (_directory, state, mut writer, task) = fixture().await;
    let ids = [0xaabb_ccdd, 0xaabb_ccff].map(|seed| {
        AccountId::try_from(account_id(AccountType::Private, AssetCallbackFlag::Disabled, seed))
            .unwrap()
    });
    assert_ne!(ids[0], ids[1]);
    assert_eq!(ids[0].prefix(), ids[1].prefix());
    let block = first_block(
        &state,
        ids[0],
        Word::from([1u32, 2, 3, 4]),
        Note::mock_noop(Word::from([5u32, 0, 0, 0])),
    )
    .await;
    writer.apply_block(block, None).await.unwrap();
    let tx =
        MockProvenTxBuilder::with_account(ids[1], Word::empty(), Word::from([2u32; 4])).build();
    let result = get_tx_inputs(&state, &tx).await;
    writer.stop(task).await;
    assert!(matches!(result,
        Err(MempoolSubmissionError::AuthenticationFailed(StateConflict::AccountIdPrefixAlreadyExists(id)))
            if id == ids[1]));
}
