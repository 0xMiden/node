use miden_protocol::transaction::ProvenTransaction;
use miden_standards::note::TxFeeNote;

use crate::errors::MempoolSubmissionError;

/// Ensures that a transaction creates a canonical fee note.
///
/// This check does not validate that the fee is sufficient for the transaction execution cost.
pub fn ensure_transaction_has_fee(tx: &ProvenTransaction) -> Result<(), MempoolSubmissionError> {
    let fee_script_root = TxFeeNote::script_root();
    let contains_fee = tx.output_notes().iter().any(|note| {
        note.recipient()
            .is_some_and(|recipient| recipient.script().root() == fee_script_root)
    });

    if contains_fee {
        Ok(())
    } else {
        Err(MempoolSubmissionError::MissingFee { transaction_id: tx.id() })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_node_proto::{BuildUnchecked, DecodeMessage};
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::transaction::{OutputNote, ProvenTransaction, PublicOutputNote};
    use miden_standards::note::TxFeeNote;

    use super::ensure_transaction_has_fee;
    use crate::errors::MempoolSubmissionError;
    use crate::test_utils::{MockAuthenticatedTxBuilder, MockProvenTxBuilder, mock_account_id};

    #[test]
    fn authenticated_transaction_proto_roundtrip_preserves_the_transaction() {
        let transaction =
            MockAuthenticatedTxBuilder::new(MockProvenTxBuilder::with_account_index(1).build())
                .build();
        let encoded = miden_node_proto::generated::sequencer::AuthenticatedTransaction::from(
            transaction.clone(),
        );
        let decoded = encoded.decode_fields().unwrap().build_unchecked().unwrap();
        assert_eq!(decoded, transaction);
    }

    fn transaction_with_fee_amount(amount: u64) -> ProvenTransaction {
        let fee_note = TxFeeNote::builder()
            .sender(mock_account_id(1))
            .serial_number(Word::from([1u32, 2, 3, 4]))
            .asset(FungibleAsset::new(FungibleAsset::mock_issuer(), amount).unwrap())
            .build()
            .unwrap()
            .into();

        MockProvenTxBuilder::with_account_index(1)
            .output_notes(vec![OutputNote::Public(PublicOutputNote::new(fee_note).unwrap())])
            .build()
    }

    #[test]
    fn transaction_fee_requires_the_canonical_note_script() {
        let tx = transaction_with_fee_amount(1);

        ensure_transaction_has_fee(&tx).unwrap();
    }

    #[test]
    fn transaction_without_fee_is_rejected() {
        let tx = MockProvenTxBuilder::with_account_index(1).build();

        assert_matches!(
            ensure_transaction_has_fee(&tx),
            Err(MempoolSubmissionError::MissingFee { transaction_id }) if transaction_id == tx.id()
        );
    }

    #[test]
    fn transaction_with_zero_fee_asset_is_accepted() {
        let tx = transaction_with_fee_amount(0);

        ensure_transaction_has_fee(&tx).unwrap();
    }
}
