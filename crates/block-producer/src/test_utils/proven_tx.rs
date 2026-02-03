use std::ops::Range;
use std::sync::Arc;

use itertools::Itertools;
use miden_node_utils::fee::test_fee;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_protocol::transaction::{
    InputNote,
    OutputNote,
    ProvenTransaction,
    ProvenTransactionBuilder,
};
use miden_protocol::vm::ExecutionProof;
use miden_protocol::{Felt, ONE, Word};
use rand::Rng;

use super::MockPrivateAccount;
use crate::domain::transaction::AuthenticatedTransaction;

#[derive(Clone)]
pub struct MockProvenTxBuilder {
    account_id: AccountId,
    initial_account_commitment: Word,
    final_account_commitment: Word,
    expiration_block_num: BlockNumber,
    output_notes: Option<Vec<OutputNote>>,
    input_notes: Option<Vec<InputNote>>,
    nullifiers: Option<Vec<Nullifier>>,
    fee: FungibleAsset,
}

impl MockProvenTxBuilder {
    pub fn with_account_index(account_index: u32) -> Self {
        let mock_account: MockPrivateAccount = account_index.into();

        Self::with_account(mock_account.id, mock_account.states[0], mock_account.states[1])
    }

    /// Generates 3 random, sequential transactions acting on the same account.
    pub fn sequential() -> [Arc<AuthenticatedTransaction>; 3] {
        let mut rng = rand::rng();
        let mock_account: MockPrivateAccount<4> = rng.random::<u32>().into();

        (0..3)
            .map(|i| {
                Self::with_account(
                    mock_account.id,
                    mock_account.states[i],
                    mock_account.states[i + 1],
                )
            })
            .map(|tx| Arc::new(AuthenticatedTransaction::from_inner(tx.build())))
            .collect_vec()
            .try_into()
            .expect("Sizes should match")
    }

    pub fn with_account(
        account_id: AccountId,
        initial_account_commitment: Word,
        final_account_commitment: Word,
    ) -> Self {
        Self {
            account_id,
            initial_account_commitment,
            final_account_commitment,
            expiration_block_num: u32::MAX.into(),
            output_notes: None,
            input_notes: None,
            nullifiers: None,
            fee: test_fee(),
        }
    }

    #[must_use]
    pub fn unauthenticated_notes(mut self, notes: Vec<Note>) -> Self {
        self.input_notes = Some(notes.into_iter().map(InputNote::unauthenticated).collect());

        self
    }

    #[must_use]
    pub fn nullifiers(mut self, nullifiers: Vec<Nullifier>) -> Self {
        self.nullifiers = Some(nullifiers);

        self
    }

    #[must_use]
    pub fn expiration_block_num(mut self, expiration_block_num: BlockNumber) -> Self {
        self.expiration_block_num = expiration_block_num;

        self
    }

    #[must_use]
    pub fn output_notes(mut self, notes: Vec<OutputNote>) -> Self {
        self.output_notes = Some(notes);

        self
    }

    #[must_use]
    pub fn nullifiers_range(self, range: Range<u64>) -> Self {
        let nullifiers = range
            .map(|index| {
                let nullifier = Word::from([ONE, ONE, ONE, Felt::new(index)]);

                Nullifier::from_raw(nullifier)
            })
            .collect();

        self.nullifiers(nullifiers)
    }

    #[must_use]
    pub fn unauthenticated_notes_range(self, range: Range<u32>) -> Self {
        let notes = range
            .map(|note_index| Note::mock_noop(Word::from([0, 0, 0, note_index])))
            .collect();

        self.unauthenticated_notes(notes)
    }

    #[must_use]
    pub fn private_notes_created_range(self, range: Range<u32>) -> Self {
        let notes = range
            .map(|note_index| {
                let note = Note::mock_noop(Word::from([0, 0, 0, note_index]));

                OutputNote::Header(note.header().clone())
            })
            .collect();

        self.output_notes(notes)
    }

    pub fn build(self) -> ProvenTransaction {
        ProvenTransactionBuilder::new(
            self.account_id,
            self.initial_account_commitment,
            self.final_account_commitment,
            Word::empty(),
            BlockNumber::GENESIS,
            Word::empty(),
            self.fee,
            self.expiration_block_num,
            ExecutionProof::new_dummy(),
        )
        .add_input_notes(self.input_notes.unwrap_or_default())
        .add_input_notes(self.nullifiers.unwrap_or_default())
        .add_output_notes(self.output_notes.unwrap_or_default())
        .build()
        .unwrap()
    }
}
