use miden_protocol::Word;
use miden_protocol::block::FeeParameters;
use miden_protocol::transaction::ProvenTransaction;
use miden_standards::note::TxFeeNote;

use crate::errors::MempoolSubmissionError;

/// Ensures that a transaction pays a non-zero fee when fees are enabled.
///
/// A zero verification base fee disables this check. Otherwise, the transaction must contain a
/// canonical fee output note with at least one non-zero asset. Validating that the amount is
/// sufficient for the transaction's execution cost is handled separately.
pub fn ensure_transaction_has_fee(
    tx: &ProvenTransaction,
    fee_parameters: &FeeParameters,
) -> Result<(), MempoolSubmissionError> {
    if fee_parameters.verification_base_fee() == 0 {
        return Ok(());
    }

    let fee_script_root = TxFeeNote::script_root();
    let contains_fee = tx.output_notes().iter().any(|note| {
        let has_fee_script = note
            .recipient()
            .is_some_and(|recipient| recipient.script().root() == fee_script_root);
        let has_non_zero_asset = note.assets().is_some_and(|assets| {
            assets.iter().any(|asset| asset.to_value_word() != Word::empty())
        });

        has_fee_script && has_non_zero_asset
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
    use miden_protocol::block::FeeParameters;
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
        // SAFETY: This test checks the round trip of a locally constructed transaction fixture.
        let decoded = encoded.decode_fields().unwrap().build_unchecked().unwrap();
        assert_eq!(decoded, transaction);
    }

    fn fee_parameters(verification_base_fee: u32) -> FeeParameters {
        FeeParameters::new(verification_base_fee)
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

        ensure_transaction_has_fee(&tx, &fee_parameters(1)).unwrap();
    }

    #[test]
    fn transaction_without_fee_is_rejected_when_fees_are_enabled() {
        let tx = MockProvenTxBuilder::with_account_index(1).build();

        assert_matches!(
            ensure_transaction_has_fee(&tx, &fee_parameters(1)),
            Err(MempoolSubmissionError::MissingFee { transaction_id }) if transaction_id == tx.id()
        );
    }

    #[test]
    fn transaction_with_zero_fee_asset_is_rejected_when_fees_are_enabled() {
        let tx = transaction_with_fee_amount(0);

        assert_matches!(
            ensure_transaction_has_fee(&tx, &fee_parameters(1)),
            Err(MempoolSubmissionError::MissingFee { transaction_id }) if transaction_id == tx.id()
        );
    }

    #[test]
    fn transaction_without_fee_is_accepted_when_fees_are_disabled() {
        let tx = MockProvenTxBuilder::with_account_index(1).build();

        ensure_transaction_has_fee(&tx, &fee_parameters(0)).unwrap();
    }
}
