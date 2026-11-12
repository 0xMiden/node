use miden_node_proto::domain::sequencer::AuthenticatedTransaction;
use miden_protocol::batch::ProvenBatch;
use miden_protocol::transaction::{PublicTransactionLogs, TransactionLogDetails, TransactionLogs};
use miden_protocol::{
    MAX_ACCOUNTS_PER_BATCH,
    MAX_INPUT_NOTES_PER_BATCH,
    MAX_OUTPUT_NOTES_PER_BATCH,
};

use crate::{DEFAULT_MAX_BATCHES_PER_BLOCK, DEFAULT_MAX_TXS_PER_BATCH};

/// Constraints placed on the batches proposed by the [`Mempool`](super::Mempool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchBudget {
    /// Maximum number of transactions allowed in a batch.
    pub transactions: usize,
    /// Maximum number of input notes allowed.
    pub input_notes: usize,
    /// Maximum number of output notes allowed.
    pub output_notes: usize,
    /// Maximum number of updated accounts.
    pub accounts: usize,
    /// Remaining public log content words.
    pub public_log_content_words: usize,
}

/// Constraints placed on the blocks proposed by the [`Mempool`](super::Mempool).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockBudget {
    /// Maximum number of batches allowed in a block.
    pub batches: usize,
    /// Remaining public log content words across all selected batches.
    pub public_log_content_words: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BudgetStatus {
    /// The operation remained within the budget.
    WithinScope,
    /// The operation exceeded the budget.
    Exceeded,
}

impl Default for BatchBudget {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_TXS_PER_BATCH.get())
    }
}

impl Default for BlockBudget {
    fn default() -> Self {
        Self {
            batches: DEFAULT_MAX_BATCHES_PER_BLOCK.get(),
            public_log_content_words: PublicTransactionLogs::MAX_NUM_WORDS,
        }
    }
}

impl BatchBudget {
    /// Creates a standalone transaction budget and reserves room for one pass-through transaction.
    pub fn new(max_transactions: usize) -> Self {
        Self {
            transactions: max_transactions.saturating_sub(1),
            input_notes: MAX_INPUT_NOTES_PER_BATCH,
            output_notes: MAX_OUTPUT_NOTES_PER_BATCH.saturating_sub(1),
            accounts: MAX_ACCOUNTS_PER_BATCH.saturating_sub(1),
            public_log_content_words: PublicTransactionLogs::MAX_NUM_WORDS
                - TransactionLogs::MAX_NUM_WORDS,
        }
    }

    /// Returns `true` if no more transaction resources can be consumed from this budget.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.transactions == 0
            || self.input_notes == 0
            || self.output_notes == 0
            || self.accounts == 0
            || self.public_log_content_words == 0
    }

    /// Attempts to consume the transaction's resources from the budget.
    ///
    /// Returns [`BudgetStatus::Exceeded`] if the transaction would exceed the remaining budget,
    /// otherwise returns [`BudgetStatus::WithinScope`] and subtracts the resources from the budget.
    #[must_use]
    pub(crate) fn check_then_subtract(&mut self, tx: &AuthenticatedTransaction) -> BudgetStatus {
        // The protocol exposes one account update per transaction. This type assertion keeps the
        // budget assumption coupled to that API.
        pub(crate) const ACCOUNT_UPDATES_PER_TX: usize = 1;
        let _: miden_protocol::account::AccountId = tx.account_update().account_id();

        let output_notes = tx.output_note_count();
        let input_notes = tx.input_note_count();
        let public_log_content_words = match tx.raw_proven_transaction().log_details() {
            TransactionLogDetails::Public(logs) => logs.num_content_words(),
            TransactionLogDetails::Private(_) => 0,
        };

        if self.transactions == 0
            || self.accounts < ACCOUNT_UPDATES_PER_TX
            || self.input_notes < input_notes
            || self.output_notes < output_notes
            || self.public_log_content_words < public_log_content_words
        {
            return BudgetStatus::Exceeded;
        }

        self.transactions -= 1;
        self.accounts -= ACCOUNT_UPDATES_PER_TX;
        self.input_notes -= input_notes;
        self.output_notes -= output_notes;
        self.public_log_content_words -= public_log_content_words;

        BudgetStatus::WithinScope
    }
}

impl BlockBudget {
    /// Attempts to consume the batch's resources from the budget.
    ///
    /// Returns [`BudgetStatus::Exceeded`] if the batch would exceed the remaining budget,
    /// otherwise returns [`BudgetStatus::WithinScope`].
    #[must_use]
    pub(crate) fn check_then_subtract(&mut self, batch: &ProvenBatch) -> BudgetStatus {
        let words = batch
            .public_logs()
            .entries()
            .iter()
            .map(|(_, logs)| logs.num_content_words())
            .sum::<usize>();
        if self.batches == 0 || self.public_log_content_words < words {
            BudgetStatus::Exceeded
        } else {
            self.batches -= 1;
            self.public_log_content_words -= words;
            BudgetStatus::WithinScope
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::code_tree::CodePatch;
    use miden_protocol::block::{BlockHeader, BlockNumber};
    use miden_protocol::testing::dummy_execution_proof;
    use miden_protocol::transaction::{
        InputNoteCommitment,
        OutputNote,
        ProvenTransaction,
        PublicOutputNote,
    };

    use super::*;
    use crate::test_utils::note::mock_fee_note;
    use crate::test_utils::{MockAuthenticatedTxBuilder, MockProvenTxBuilder};

    #[test]
    fn batch_budget_reserves_pass_through_transaction_resources() {
        let budget = BatchBudget::new(10);

        assert_eq!(budget.transactions, 9);
        assert_eq!(budget.accounts, MAX_ACCOUNTS_PER_BATCH - 1);
        assert_eq!(budget.output_notes, MAX_OUTPUT_NOTES_PER_BATCH - 1);
        assert_eq!(budget.input_notes, MAX_INPUT_NOTES_PER_BATCH);
    }

    #[test]
    fn fee_notes_consume_the_output_note_budget() {
        let fee_note = mock_fee_note(1);
        let tx = MockProvenTxBuilder::with_account_index(1)
            .output_notes(vec![OutputNote::Public(PublicOutputNote::new(fee_note).unwrap())])
            .build();
        let tx = MockAuthenticatedTxBuilder::new(tx).build();
        let mut budget = BatchBudget::new(10);
        let initial_output_notes = budget.output_notes;

        assert_eq!(budget.check_then_subtract(&tx), BudgetStatus::WithinScope);
        assert_eq!(budget.output_notes, initial_output_notes - 1);
    }

    fn public_transaction(words: usize) -> ProvenTransaction {
        public_transaction_at(words, 1)
    }

    fn public_transaction_at(words: usize, state: u32) -> ProvenTransaction {
        use miden_protocol::Word;
        use miden_protocol::account::{
            AccountCodePatch,
            AccountPatch,
            AccountStoragePatch,
            AccountUpdateDetails,
            AccountVaultPatch,
        };
        use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
        use miden_protocol::transaction::{
            LogTopic,
            TransactionLog,
            TransactionLogDetails,
            TransactionLogs,
            TxAccountUpdate,
        };
        let id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
        let patch = AccountPatch::new(
            id,
            AccountStoragePatch::default(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some((state + 1).into()),
        )
        .unwrap();
        let update = TxAccountUpdate::new(
            id,
            Word::from([state; 4]),
            Word::from([state + 1; 4]),
            patch.to_commitment(),
            AccountUpdateDetails::Public(patch),
        )
        .unwrap();
        let logs = TransactionLogs::new(vec![
            TransactionLog::new(
                id,
                LogTopic::new(1_u32.into(), 2_u32.into()),
                vec![Word::empty(); words],
            )
            .unwrap(),
        ])
        .unwrap();
        ProvenTransaction::new(
            update,
            Vec::<InputNoteCommitment>::new(),
            Vec::<OutputNote>::new(),
            BlockNumber::GENESIS,
            Word::empty(),
            BlockNumber::MAX,
            dummy_execution_proof(),
            TransactionLogDetails::Public(logs),
            CodePatch::default(),
        )
        .unwrap()
    }

    #[test]
    fn public_log_batch_budget_reserves_fee_headroom_and_rejection_is_atomic() {
        let tx = MockAuthenticatedTxBuilder::new(public_transaction(64)).build();
        let mut budget = BatchBudget::new(1024);
        for _ in 0..511 {
            assert_eq!(budget.check_then_subtract(&tx), BudgetStatus::WithinScope);
        }
        let before = budget.clone();
        assert_eq!(budget.check_then_subtract(&tx), BudgetStatus::Exceeded);
        assert_eq!(budget, before);
        let empty = MockAuthenticatedTxBuilder::new(public_transaction(0)).build();
        assert_eq!(budget.check_then_subtract(&empty), BudgetStatus::WithinScope);
        let private =
            MockAuthenticatedTxBuilder::new(MockProvenTxBuilder::with_account_index(1).build())
                .build();
        assert_eq!(budget.check_then_subtract(&private), BudgetStatus::WithinScope);
    }

    #[test]
    fn public_log_block_budget_charges_proven_batches_without_fee_reservation() {
        use crate::test_utils::batch::TransactionBatchConstructor;
        let transaction = public_transaction(64);
        let batch = ProvenBatch::mocked_from_transactions([&transaction]);
        let mut budget = BlockBudget { batches: 1024, ..BlockBudget::default() };
        for _ in 0..512 {
            assert_eq!(budget.check_then_subtract(&batch), BudgetStatus::WithinScope);
        }
        let before = budget;
        assert_eq!(budget.check_then_subtract(&batch), BudgetStatus::Exceeded);
        assert_eq!(budget, before);
    }

    #[test]
    fn public_log_budget_defers_a_batch_until_the_next_block() {
        use std::sync::Arc;

        use crate::mempool::{Mempool, MempoolConfig};
        use crate::test_utils::batch::TransactionBatchConstructor;
        let config = MempoolConfig {
            block_budget: BlockBudget {
                public_log_content_words: 64,
                ..BlockBudget::default()
            },
            ..MempoolConfig::default()
        };
        let mut mempool = Mempool::new(BlockNumber::GENESIS, config);
        let mut ids = Vec::new();
        for state in [1, 2] {
            let transaction =
                Arc::new(MockAuthenticatedTxBuilder::new(public_transaction_at(64, state)).build());
            let proof =
                ProvenBatch::mocked_from_transactions([transaction.raw_proven_transaction()]);
            ids.push(proof.id());
            mempool.add_transaction(transaction).unwrap();
            assert!(mempool.select_any_batch().is_some());
            mempool.commit_batch(Arc::new(proof));
        }
        let first = mempool.select_block();
        assert_eq!(first.batches.iter().map(|batch| batch.id()).collect::<Vec<_>>(), vec![ids[0]]);
        mempool.commit_block(&BlockHeader::mock(1, None, None, &[]));
        let second = mempool.select_block();
        assert_eq!(second.batches.iter().map(|batch| batch.id()).collect::<Vec<_>>(), vec![ids[1]]);
    }

    #[test]
    fn full_batch_selection_recognizes_exhausted_public_log_budget() {
        use std::sync::Arc;

        use crate::mempool::{Mempool, MempoolConfig};
        let config = MempoolConfig {
            batch_budget: BatchBudget::new(1024),
            max_txs_per_batch: 1024,
            ..MempoolConfig::default()
        };
        let mut mempool = Mempool::new(BlockNumber::GENESIS, config);
        for state in 1..=511 {
            let tx = MockAuthenticatedTxBuilder::new(public_transaction_at(64, state)).build();
            mempool.add_transaction(Arc::new(tx)).unwrap();
        }
        let batch = mempool.select_full_batch().expect("content-saturated work is a full batch");
        assert_eq!(batch.transactions().len(), 511);
    }
}
