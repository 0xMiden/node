use std::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::batch::{BatchAccountUpdate, BatchId, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
    ProvenTransaction,
    TransactionHeader,
};

use crate::test_utils::MockProvenTxBuilder;

pub trait TransactionBatchConstructor {
    /// Builds a **mocked** [`ProvenBatch`] from the given transactions, which most likely violates
    /// some of the rules of actual transaction batches.
    ///
    /// This builds a mocked version of a proven batch for testing purposes which can be useful if
    /// the batch's details don't need to be correct (e.g. if something else is under test but
    /// requires a transaction batch). If you need an actual valid [`ProvenBatch`], build a
    /// [`ProposedBatch`](miden_protocol::batch::ProposedBatch) first and convert (without proving)
    /// or prove it into a [`ProvenBatch`].
    fn mocked_from_transactions<'tx>(txs: impl IntoIterator<Item = &'tx ProvenTransaction>)
    -> Self;

    /// Returns a `TransactionBatch` with `notes_per_tx.len()` transactions, where the i'th
    /// transaction has `notes_per_tx[i]` notes created
    fn from_notes_created(starting_account_index: u32, notes_per_tx: &[u32]) -> Self;

    /// Returns a `TransactionBatch` which contains `num_txs_in_batch` transactions
    fn from_txs(starting_account_index: u32, num_txs_in_batch: u64) -> Self;
}

impl TransactionBatchConstructor for ProvenBatch {
    fn mocked_from_transactions<'tx>(
        txs: impl IntoIterator<Item = &'tx ProvenTransaction>,
    ) -> Self {
        let mut account_updates = BTreeMap::new();

        let txs: Vec<_> = txs.into_iter().collect();
        let mut input_notes = Vec::new();
        let mut output_notes = Vec::new();

        for tx in &txs {
            // Aggregate account updates.
            account_updates
                .entry(tx.account_id())
                .and_modify(|update: &mut BatchAccountUpdate| {
                    update.merge_proven_tx(tx).unwrap();
                })
                .or_insert_with(|| BatchAccountUpdate::from_transaction(tx));

            // Consider all input notes of all transactions as inputs of the batch, which may not
            // always be correct.
            input_notes.extend(tx.input_notes().iter().cloned());
            // Consider all outputs notes of all transactions as outputs of the batch, which may not
            // always be correct.
            output_notes.extend(tx.output_notes().iter().cloned());
        }

        ProvenBatch::new(
            BatchId::from_transactions(txs.iter().copied()),
            Word::empty(),
            BlockNumber::GENESIS,
            account_updates,
            InputNotes::new_unchecked(input_notes),
            output_notes,
            BlockNumber::MAX,
            OrderedTransactionHeaders::new_unchecked(
                txs.into_iter().map(TransactionHeader::from).collect(),
            ),
        )
        .unwrap()
    }

    fn from_notes_created(starting_account_index: u32, notes_per_tx: &[u32]) -> Self {
        let txs: Vec<_> = notes_per_tx
            .iter()
            .enumerate()
            .map(|(index, &num_notes)| {
                let starting_note_index = starting_account_index + index as u32;
                MockProvenTxBuilder::with_account_index(starting_account_index + index as u32)
                    .private_notes_created_range(
                        starting_note_index..(starting_note_index + num_notes),
                    )
                    .build()
            })
            .collect();

        Self::mocked_from_transactions(&txs)
    }

    fn from_txs(starting_account_index: u32, num_txs_in_batch: u64) -> Self {
        let txs: Vec<_> = (0..num_txs_in_batch)
            .enumerate()
            .map(|(index, _)| {
                MockProvenTxBuilder::with_account_index(starting_account_index + index as u32)
                    .build()
            })
            .collect();

        Self::mocked_from_transactions(&txs)
    }
}
