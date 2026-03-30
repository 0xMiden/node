use miden_protocol::batch::ProvenBatch;
use miden_protocol::{
    MAX_ACCOUNTS_PER_BATCH,
    MAX_INPUT_NOTES_PER_BATCH,
    MAX_OUTPUT_NOTES_PER_BATCH,
};

use crate::domain::transaction::AuthenticatedTransaction;
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
    ///
    /// Authenticated transactions are assumed to update at most one account; this field enforces
    /// how many such single-account updates can fit into a batch.
    pub accounts: usize,
}

/// Constraints placed on the blocks proposed by the [`Mempool`](super::Mempool).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockBudget {
    /// Maximum number of batches allowed in a block.
    pub batches: usize,
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
            transactions: DEFAULT_MAX_TXS_PER_BATCH,
            input_notes: MAX_INPUT_NOTES_PER_BATCH,
            output_notes: MAX_OUTPUT_NOTES_PER_BATCH,
            accounts: MAX_ACCOUNTS_PER_BATCH,
        }
    }
}

impl Default for BlockBudget {
    fn default() -> Self {
        Self { batches: DEFAULT_MAX_BATCHES_PER_BLOCK }
    }
}

impl BatchBudget {
    /// Attempts to consume the transaction's resources from the budget.
    ///
    /// Returns [`BudgetStatus::Exceeded`] if the transaction would exceed the remaining budget,
    /// otherwise returns [`BudgetStatus::WithinScope`] and subtracts the resources from the budget.
    #[must_use]
    pub(crate) fn check_then_subtract(&mut self, tx: &AuthenticatedTransaction) -> BudgetStatus {
        // This type assertion reminds us to update the account check if we ever support
        // multiple account updates per tx.
        pub(crate) const ACCOUNT_UPDATES_PER_TX: usize = 1;
        let _: miden_protocol::account::AccountId = tx.account_update().account_id();

        let output_notes = tx.output_note_count();
        let input_notes = tx.input_note_count();

        if self.transactions == 0
            || self.accounts < ACCOUNT_UPDATES_PER_TX
            || self.input_notes < input_notes
            || self.output_notes < output_notes
        {
            return BudgetStatus::Exceeded;
        }

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
    pub(crate) fn check_then_subtract(&mut self, _batch: &ProvenBatch) -> BudgetStatus {
        if self.batches == 0 {
            BudgetStatus::Exceeded
        } else {
            self.batches -= 1;
            BudgetStatus::WithinScope
        }
    }
}
