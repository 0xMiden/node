use miden_protocol::Word;
use miden_protocol::account::{AccountDelta, AccountId};
use miden_protocol::transaction::{ExecutedTransaction, InputNote, InputNotes, OutputNotes};
use miden_tx::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Contains the information about a validated transaction that the Validator, or some ad-hoc
/// auditing procedure, might require.
///
/// Constructed from an [`ExecutedTransaction`] that the Validator would have created while
/// validating a [`miden_protocol::transaction::ProvenTransaction`].
pub struct ValidatedTransactionInfo {
    initial_account_state_commitment: Word,
    final_account_state_commitment: Word,
    account_delta: AccountDelta,
    input_notes: InputNotes<InputNote>,
    output_notes: OutputNotes,
}

impl ValidatedTransactionInfo {
    /// Returns a reference to the account Id pertaining to the validated transaction.
    pub fn account_id(&self) -> AccountId {
        self.account_delta.id()
    }
}

impl From<ExecutedTransaction> for ValidatedTransactionInfo {
    fn from(executed_tx: ExecutedTransaction) -> Self {
        let initial_account_state_commitment = executed_tx.initial_account().initial_commitment();
        let final_account_state_commitment = executed_tx.final_account().commitment();
        let (tx_inputs, tx_outputs, account_delta, _) = executed_tx.into_parts();
        let (_, _, _, input_notes, _) = tx_inputs.into_parts();
        let output_notes = tx_outputs.output_notes;
        Self {
            initial_account_state_commitment,
            final_account_state_commitment,
            account_delta,
            input_notes,
            output_notes,
        }
    }
}

impl Serializable for ValidatedTransactionInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.initial_account_state_commitment);
        target.write(self.final_account_state_commitment);
        target.write(&self.account_delta);
        target.write(&self.input_notes);
        target.write(&self.output_notes);
    }
}

impl Deserializable for ValidatedTransactionInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let initial_account_state_commitment = source.read()?;
        let final_account_state_commitment = source.read()?;
        let account_delta = source.read()?;
        let input_notes = source.read()?;
        let output_notes = source.read()?;
        Ok(Self {
            initial_account_state_commitment,
            final_account_state_commitment,
            account_delta,
            input_notes,
            output_notes,
        })
    }
}
