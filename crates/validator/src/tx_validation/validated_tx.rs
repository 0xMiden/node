use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{ExecutedTransaction, TransactionId};
use miden_tx::utils::Serializable;

/// Re-executed and validated transaction that the Validator, or some ad-hoc
/// auditing procedure, might need to analyze.
///
/// Constructed from an [`ExecutedTransaction`] that the Validator would have created while
/// re-executing and validating a [`miden_protocol::transaction::ProvenTransaction`].
pub struct ValidatedTransaction(ExecutedTransaction);

impl ValidatedTransaction {
    /// Creates a new instance of [`ValidatedTransactionInfo`].
    pub fn new(tx: ExecutedTransaction) -> Self {
        Self(tx)
    }

    /// Returns ID of the transaction.
    pub fn tx_id(&self) -> TransactionId {
        self.0.id()
    }

    /// Returns the block number in which the transaction was executed.
    pub fn block_num(&self) -> BlockNumber {
        self.0.block_header().block_num()
    }

    /// Returns ID of the account against which this transaction was executed.
    pub fn account_id(&self) -> AccountId {
        self.0.account_delta().id()
    }

    /// Returns the binary representation of the transaction info.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
