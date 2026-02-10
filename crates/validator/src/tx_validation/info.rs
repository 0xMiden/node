use miden_protocol::Word;
use miden_protocol::account::{AccountDelta, AccountId};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{
    ExecutedTransaction,
    InputNote,
    InputNotes,
    OutputNotes,
    TransactionId,
};
use miden_tx::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Contains the information about a validated transaction that the Validator, or some ad-hoc
/// auditing procedure, might require.
///
/// Constructed from an [`ExecutedTransaction`] that the Validator would have created while
/// validating a [`miden_protocol::transaction::ProvenTransaction`].
pub struct ValidatedTransactionInfo {
    tx_id: TransactionId,
    block_num: BlockNumber,
    blob: ValidatedTransactionInfoBlob,
}

/// The data of [`ValidatedTransactionInfo`] which is serialized into a byte array and stored as a
/// column in the `validated_transactions` table.
struct ValidatedTransactionInfoBlob {
    initial_account_state_commitment: Word,
    final_account_state_commitment: Word,
    account_delta: AccountDelta,
    input_notes: InputNotes<InputNote>,
    output_notes: OutputNotes,
}

impl ValidatedTransactionInfo {
    /// Returns ID of the transaction.
    pub fn tx_id(&self) -> TransactionId {
        self.tx_id
    }

    /// Returns the block number in which the transaction was executed.
    pub fn block_num(&self) -> BlockNumber {
        self.block_num
    }

    /// Returns ID of the account against which this transaction was executed.
    pub fn account_id(&self) -> AccountId {
        self.blob.account_delta.id()
    }

    /// Returns the binary representation of the transaction info.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.blob.to_bytes()
    }
}

impl From<ExecutedTransaction> for ValidatedTransactionInfo {
    fn from(executed_tx: ExecutedTransaction) -> Self {
        let tx_id = executed_tx.id();
        let block_num = executed_tx.block_header().block_num();
        let initial_account_state_commitment = executed_tx.initial_account().initial_commitment();
        let final_account_state_commitment = executed_tx.final_account().commitment();
        let (tx_inputs, tx_outputs, account_delta, _) = executed_tx.into_parts();
        let (_, _, _, input_notes, _) = tx_inputs.into_parts();
        let output_notes = tx_outputs.output_notes;
        let blob = ValidatedTransactionInfoBlob {
            initial_account_state_commitment,
            final_account_state_commitment,
            account_delta,
            input_notes,
            output_notes,
        };
        Self { tx_id, block_num, blob }
    }
}

impl Serializable for ValidatedTransactionInfoBlob {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.initial_account_state_commitment);
        target.write(self.final_account_state_commitment);
        target.write(&self.account_delta);
        target.write(&self.input_notes);
        target.write(&self.output_notes);
    }
}

impl Deserializable for ValidatedTransactionInfoBlob {
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
