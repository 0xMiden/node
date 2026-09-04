use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::BatchId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;

use crate::domain::transaction::AuthenticatedTransaction;

// SELECTED BATCH
// ================================================================================================

/// Identifies a transaction selection in the batch graph.
///
/// A sequencer-built batch has a different [`BatchId`] after the batch builder appends the fee
/// transaction. A user-proven batch keeps the same ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SelectedBatchId(BatchId);

impl SelectedBatchId {
    pub(crate) fn from_batch_id(batch_id: BatchId) -> Self {
        Self(batch_id)
    }

    pub(crate) fn as_batch_id(self) -> BatchId {
        self.0
    }
}

impl Display for SelectedBatchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Parameters that define how the node builds a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BatchParameters {
    pub reference_block: BlockNumber,
}

#[cfg(test)]
impl BatchParameters {
    pub(crate) fn for_tests() -> Self {
        Self { reference_block: BlockNumber::GENESIS }
    }
}

/// A sequence of transactions selected by the [`Mempool`] to be processed by the
/// [`BatchBuilder`] into a [`ProposedBatch`], and then finally into a [`ProvenBatch`].
///
/// [Mempool]: crate::mempool::Mempool
/// [BatchBuilder]: crate::batch_builder::BatchBuilder
/// [ProposedBatch]: miden_protocol::batch::ProposedBatch
/// [ProvenBatch]: miden_protocol::batch::ProvenBatch
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SelectedBatch {
    txs: Vec<Arc<AuthenticatedTransaction>>,
    id: SelectedBatchId,
    parameters: BatchParameters,
    account_updates: HashMap<AccountId, (Word, Word, Option<Word>)>,
    unauthenticated_notes: HashSet<Word>,
    collectible_fee_notes: Vec<Note>,
}

impl SelectedBatch {
    pub(crate) fn builder(parameters: BatchParameters) -> SelectedBatchBuilder {
        SelectedBatchBuilder {
            parameters,
            txs: Vec::new(),
            account_updates: HashMap::new(),
        }
    }

    pub(crate) fn id(&self) -> SelectedBatchId {
        self.id
    }

    pub(crate) fn into_transactions(self) -> Vec<Arc<AuthenticatedTransaction>> {
        self.txs
    }

    pub(crate) fn transactions(&self) -> &[Arc<AuthenticatedTransaction>] {
        &self.txs
    }

    pub(crate) fn parameters(&self) -> BatchParameters {
        self.parameters
    }

    pub(crate) fn collectible_fee_notes(&self) -> &[Note] {
        &self.collectible_fee_notes
    }

    /// The aggregated list of account transitions this batch causes given as tuples of `(AccountId,
    /// initial commitment, final commitment, Option<store commitment>)`.
    ///
    /// Note that the updates are aggregated, i.e. only a single update per account is possible, and
    /// transaction updates to an account of `a -> b -> c` will result in a single `a -> c`.
    pub(crate) fn account_updates(
        &self,
    ) -> impl Iterator<Item = (AccountId, Word, Word, Option<Word>)> {
        self.account_updates
            .iter()
            .map(|(account, (from, to, store))| (*account, *from, *to, *store))
    }

    pub(crate) fn unauthenticated_note_commitments(&self) -> impl Iterator<Item = Word> {
        self.unauthenticated_notes.iter().copied()
    }

    pub(crate) fn expires_at(&self) -> BlockNumber {
        self.txs
            .iter()
            .map(|tx| tx.expires_at().as_u32())
            .min()
            .unwrap_or(u32::MAX)
            .into()
    }
}

/// A builder to construct a [`SelectedBatch`].
#[derive(Clone)]
pub(crate) struct SelectedBatchBuilder {
    parameters: BatchParameters,
    pub(crate) txs: Vec<Arc<AuthenticatedTransaction>>,
    pub(crate) account_updates: HashMap<AccountId, (Word, Word, Option<Word>)>,
}

impl SelectedBatchBuilder {
    /// Appends the given transaction to the current batch.
    ///
    /// # Panics
    ///
    /// Panics if the new transaction's account update is inconsistent with the current account
    /// state within the batch i.e. if the transaction's initial account commitment does not
    /// match the account update's final account commitment within the batch (if any).
    pub(crate) fn push(&mut self, tx: Arc<AuthenticatedTransaction>) {
        let update = tx.account_update();
        self.account_updates
            .entry(update.account_id())
            .and_modify(|(_from, to, _store)| {
                assert!(
                    to == &update.initial_state_commitment(),
                    "Cannot select transaction {} as its initial commitment {} for account {} does \
not match the current commitment {}",
                    tx.id(),
                    update.initial_state_commitment(),
                    update.account_id(),
                    to
                );

                *to = update.final_state_commitment();
            })
            .or_insert((
                update.initial_state_commitment(),
                update.final_state_commitment(),
                tx.store_account_state(),
            ));

        self.txs.push(tx);
    }

    /// Returns `true` if it contains no transactions.
    pub(crate) fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Finalizes the batch selection.
    pub(crate) fn build(self) -> SelectedBatch {
        let Self { parameters, txs, account_updates } = self;
        let id = SelectedBatchId::from_batch_id(BatchId::from_ids(
            txs.iter().map(|tx| (tx.id(), tx.account_id())),
        ));

        let mut unauthenticated_notes: HashSet<_> =
            txs.iter().flat_map(|tx| tx.unauthenticated_note_ids()).collect();

        for output_note in txs.iter().flat_map(|tx| tx.output_note_ids()) {
            unauthenticated_notes.remove(&output_note);
        }

        let collectible_fee_notes = txs.iter().flat_map(|tx| tx.fee_notes()).cloned().collect();

        SelectedBatch {
            txs,
            id,
            parameters,
            account_updates,
            unauthenticated_notes,
            collectible_fee_notes,
        }
    }
}
