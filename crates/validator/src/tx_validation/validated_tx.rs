use miden_protocol::Word;
use miden_protocol::account::{AccountDelta, AccountId};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{
    ExecutedTransaction,
    InputNote,
    InputNotes,
    OutputNotes,
    TransactionId,
};

/// Re-executed and validated transaction that the Validator, or some ad-hoc
/// auditing procedure, might need to analyze.
///
/// Constructed from an [`ExecutedTransaction`] that the Validator would have created while
/// re-executing and validating a [`miden_protocol::transaction::ProvenTransaction`].
pub struct ValidatedTransaction(ExecutedTransaction);

impl ValidatedTransaction {
    /// Creates a new instance of [`ValidatedTransaction`].
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
        self.0.account_id()
    }

    /// Returns a description of changes between the initial and final account states.
    pub fn account_delta(&self) -> &AccountDelta {
        self.0.account_delta()
    }

    /// Returns the notes consumed in this transaction.
    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        self.0.input_notes()
    }

    /// Returns the notes created in this transaction.
    pub fn output_notes(&self) -> &OutputNotes {
        self.0.output_notes()
    }

    /// Returns the commitment of the initial account state.
    pub fn initial_account_hash(&self) -> Word {
        self.0.initial_account().initial_commitment()
    }

    /// Returns the commitment of the final account state.
    pub fn final_account_hash(&self) -> Word {
        self.0.final_account().to_commitment()
    }

    /// Returns the fee of the transaction.
    pub fn fee(&self) -> FungibleAsset {
        self.0.fee()
    }
}
