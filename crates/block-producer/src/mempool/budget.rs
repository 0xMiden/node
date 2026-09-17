use miden_node_proto::domain::sequencer::AuthenticatedTransaction;
use miden_protocol::batch::ProvenBatch;
use miden_protocol::transaction::TransactionLogData;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{
    MAX_ACCOUNTS_PER_BATCH,
    MAX_INPUT_NOTES_PER_BATCH,
    MAX_OUTPUT_NOTES_PER_BATCH,
};

use crate::{DEFAULT_MAX_BATCHES_PER_BLOCK, DEFAULT_MAX_TXS_PER_BATCH};

/// Constraints placed on the batches proposed by the [`Mempool`](super::Mempool).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BatchBudget {
    /// Maximum number of transactions allowed in a batch.
    pub transactions: usize,
    /// Maximum number of input notes allowed.
    pub input_notes: usize,
    /// Maximum number of output notes allowed.
    pub output_notes: usize,
    /// Maximum number of updated accounts.
    pub accounts: usize,
    pub log_records: usize,
    pub log_payload_words: usize,
    pub log_bytes: usize,
}

/// Constraints placed on the blocks proposed by the [`Mempool`](super::Mempool).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockBudget {
    /// Maximum number of batches allowed in a block.
    pub batches: usize,
    pub transactions: usize,
    pub log_records: usize,
    pub log_payload_words: usize,
    pub log_bytes: usize,
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
        Self {
            transactions: DEFAULT_MAX_TXS_PER_BATCH.get(),
            input_notes: MAX_INPUT_NOTES_PER_BATCH,
            output_notes: MAX_OUTPUT_NOTES_PER_BATCH,
            accounts: MAX_ACCOUNTS_PER_BATCH,
            log_records: miden_protocol::MAX_PUBLIC_LOGS_PER_BATCH,
            log_payload_words: miden_protocol::MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
            log_bytes: miden_protocol::MAX_LOG_DATA_BYTES_PER_BATCH - 4,
        }
    }
}

impl Default for BlockBudget {
    fn default() -> Self {
        Self {
            batches: DEFAULT_MAX_BATCHES_PER_BLOCK.get(),
            transactions: miden_protocol::MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
            log_records: miden_protocol::MAX_PUBLIC_LOGS_PER_BLOCK,
            log_payload_words: miden_protocol::MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
            log_bytes: miden_protocol::MAX_LOG_DATA_BYTES_PER_BLOCK - 4,
        }
    }
}

impl BatchBudget {
    /// Returns `true` if no more transaction resources can be consumed from this budget.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.transactions == 0
            || self.input_notes == 0
            || self.output_notes == 0
            || self.accounts == 0
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

        let (log_records, log_payload_words, log_bytes) =
            log_resources(tx.raw_proven_transaction().log_data());
        let output_notes = tx.output_note_count();
        let input_notes = tx.input_note_count();

        if self.transactions == 0
            || self.accounts < ACCOUNT_UPDATES_PER_TX
            || self.input_notes < input_notes
            || self.output_notes < output_notes
            || self.log_records < log_records
            || self.log_payload_words < log_payload_words
            || self.log_bytes < log_bytes
        {
            return BudgetStatus::Exceeded;
        }

        self.log_records -= log_records;
        self.log_payload_words -= log_payload_words;
        self.log_bytes -= log_bytes;
        self.transactions -= 1;
        self.accounts -= ACCOUNT_UPDATES_PER_TX;
        self.input_notes -= input_notes;
        self.output_notes -= output_notes;

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
        let transactions = batch.transactions().as_slice().len();
        let (mut count, mut words, mut bytes) = (0, 0, 0);
        for data in batch.log_data().as_slice() {
            let usage = log_resources(data);
            count += usage.0;
            words += usage.1;
            bytes += usage.2;
        }
        if self.batches == 0
            || self.transactions < transactions
            || self.log_records < count
            || self.log_payload_words < words
            || self.log_bytes < bytes
        {
            BudgetStatus::Exceeded
        } else {
            self.transactions -= transactions;
            self.log_records -= count;
            self.log_payload_words -= words;
            self.log_bytes -= bytes;
            self.batches -= 1;
            BudgetStatus::WithinScope
        }
    }
}

fn log_resources(data: &TransactionLogData) -> (usize, usize, usize) {
    let (count, words) = match data {
        TransactionLogData::Public(logs) => (
            logs.num_logs(),
            logs.iter()
                .map(miden_protocol::transaction::TransactionLog::num_payload_words)
                .sum(),
        ),
        TransactionLogData::Private(_) => (0, 0),
    };
    (count, words, data.get_size_hint() + 4)
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::account::{AccountId, AccountPatch, AccountUpdateDetails};
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
    use miden_protocol::transaction::{
        LogTopic,
        ProvenTransaction,
        TransactionLog,
        TransactionLogs,
        TxAccountUpdate,
    };

    use super::*;
    use crate::test_utils::batch::TransactionBatchConstructor;

    fn public_transaction() -> ProvenTransaction {
        let account =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap();
        let patch = AccountPatch::empty(account);
        let update = TxAccountUpdate::new(
            account,
            Word::from([1u32; 4]),
            Word::from([2u32; 4]),
            patch.to_commitment(),
            AccountUpdateDetails::Public(patch),
        )
        .unwrap();
        let logs = TransactionLogs::new(vec![
            TransactionLog::new(
                account,
                LogTopic::new([1u32.into(), 2u32.into()]),
                vec![Word::from([42u32; 4]); 2],
            )
            .unwrap(),
        ])
        .unwrap();
        ProvenTransaction::new(
            update,
            Vec::<miden_protocol::transaction::InputNoteCommitment>::new(),
            Vec::<miden_protocol::transaction::OutputNote>::new(),
            0.into(),
            Word::empty(),
            u32::MAX.into(),
            miden_protocol::testing::dummy_execution_proof(),
        )
        .unwrap()
        .with_log_data(TransactionLogData::Public(logs))
        .unwrap()
    }

    #[test]
    fn batch_log_budgets_reject_without_consuming_other_resources() {
        let tx = crate::test_utils::MockAuthenticatedTxBuilder::new(public_transaction()).build();
        let bytes = tx.raw_proven_transaction().log_data().get_size_hint() + 4;
        for mut budget in [
            BatchBudget { log_records: 0, ..Default::default() },
            BatchBudget {
                log_payload_words: 1,
                ..Default::default()
            },
            BatchBudget {
                log_bytes: bytes - 1,
                ..Default::default()
            },
        ] {
            let before = budget;
            assert_eq!(budget.check_then_subtract(&tx), BudgetStatus::Exceeded);
            assert_eq!(budget, before);
        }
        let mut budget = BatchBudget {
            log_records: 1,
            log_payload_words: 2,
            log_bytes: bytes,
            ..Default::default()
        };
        assert_eq!(budget.check_then_subtract(&tx), BudgetStatus::WithinScope);
        assert_eq!((budget.log_records, budget.log_payload_words, budget.log_bytes), (0, 0, 0));
    }

    #[test]
    fn block_log_budgets_preserve_capacity_on_rejection() {
        let tx = public_transaction();
        let batch = ProvenBatch::mocked_from_transactions([&tx]);
        for mut budget in [
            BlockBudget { transactions: 0, ..Default::default() },
            BlockBudget { log_records: 0, ..Default::default() },
            BlockBudget {
                log_payload_words: 1,
                ..Default::default()
            },
            BlockBudget { log_bytes: 0, ..Default::default() },
        ] {
            let before = budget;
            assert_eq!(budget.check_then_subtract(&batch), BudgetStatus::Exceeded);
            assert_eq!(budget, before);
        }
        let mut budget = BlockBudget::default();
        assert_eq!(budget.check_then_subtract(&batch), BudgetStatus::WithinScope);
        assert_eq!(budget.log_records, miden_protocol::MAX_PUBLIC_LOGS_PER_BLOCK - 1);
    }
}
