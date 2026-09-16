use miden_protocol::asset::AssetId;
use miden_protocol::transaction::{OutputNote, ProvenTransaction};
use miden_standards::note::TxFeeNote;

use crate::errors::MempoolSubmissionError;

/// Ensures that a transaction creates a canonical fee note with the native asset.
/// All canonical fee notes must contain exactly one asset with the specified ID.
///
/// This check does not validate that the fee is sufficient for the transaction execution cost.
pub fn ensure_transaction_has_fee(
    tx: &ProvenTransaction,
    fee_asset_id: AssetId,
) -> Result<(), MempoolSubmissionError> {
    let fee_script_root = TxFeeNote::script_root();
    let mut contains_fee = false;
    for note in tx.output_notes().iter() {
        let OutputNote::Public(note) = note else {
            continue;
        };
        if note.recipient().script().root() != fee_script_root {
            continue;
        }
        if !matches!(note.assets().as_slice(), [asset] if asset.id() == fee_asset_id) {
            return Err(MempoolSubmissionError::InvalidFeeAsset {
                transaction_id: tx.id(),
                fee_asset_id,
            });
        }
        contains_fee = true;
    }

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
    use miden_protocol::asset::{Asset, AssetId, FungibleAsset};
    use miden_protocol::note::{Note, NoteAssets};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
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
        MockProvenTxBuilder::with_account_index(1)
            .output_notes(vec![fee_output_note(
                &[FungibleAsset::new(FungibleAsset::mock_issuer(), amount).unwrap().into()],
                1,
            )])
            .build()
    }

    fn fee_asset_id() -> AssetId {
        AssetId::new_fungible(FungibleAsset::mock_issuer())
    }

    fn fee_output_note(assets: &[Asset], serial: u32) -> OutputNote {
        let template: Note = TxFeeNote::builder()
            .sender(mock_account_id(1))
            .serial_number(Word::from([serial, 2, 3, 4]))
            .asset(FungibleAsset::new(FungibleAsset::mock_issuer(), 1).unwrap())
            .build()
            .unwrap()
            .into();
        let note = Note::new(
            NoteAssets::new(assets.to_vec()).unwrap(),
            *template.metadata().partial_metadata(),
            template.recipient().clone(),
        );
        OutputNote::Public(PublicOutputNote::new(note).unwrap())
    }

    #[test]
    fn transaction_fee_requires_the_canonical_note_script() {
        let tx = transaction_with_fee_amount(1);

        ensure_transaction_has_fee(&tx, fee_asset_id()).unwrap();
    }

    #[test]
    fn transaction_without_fee_is_rejected() {
        let tx = MockProvenTxBuilder::with_account_index(1).build();

        assert_matches!(
            ensure_transaction_has_fee(&tx, fee_asset_id()),
            Err(MempoolSubmissionError::MissingFee { transaction_id }) if transaction_id == tx.id()
        );
    }

    #[test]
    fn transaction_with_zero_fee_asset_is_accepted() {
        let tx = transaction_with_fee_amount(0);

        ensure_transaction_has_fee(&tx, fee_asset_id()).unwrap();
    }

    #[test]
    fn fee_notes_must_contain_only_the_native_asset() {
        let native = FungibleAsset::new(FungibleAsset::mock_issuer(), 1).unwrap().into();
        let foreign_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
        let foreign = FungibleAsset::new(foreign_faucet, 1).unwrap().into();
        let zero_foreign = FungibleAsset::new(foreign_faucet, 0).unwrap().into();
        for assets in [vec![], vec![foreign], vec![zero_foreign], vec![native, foreign]] {
            let tx = MockProvenTxBuilder::with_account_index(1)
                .output_notes(vec![fee_output_note(&assets, 1)])
                .build();
            assert_matches!(
                ensure_transaction_has_fee(&tx, fee_asset_id()),
                Err(MempoolSubmissionError::InvalidFeeAsset { transaction_id, .. })
                    if transaction_id == tx.id()
            );
        }
    }

    #[test]
    fn native_fee_note_does_not_allow_other_fee_notes_with_foreign_assets() {
        let native = FungibleAsset::new(FungibleAsset::mock_issuer(), 1).unwrap().into();
        let foreign =
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(), 1)
                .unwrap()
                .into();
        for assets in [[native, foreign], [foreign, native]] {
            let tx = MockProvenTxBuilder::with_account_index(1)
                .output_notes(vec![
                    fee_output_note(&assets[..1], 1),
                    fee_output_note(&assets[1..], 2),
                ])
                .build();
            assert_matches!(
                ensure_transaction_has_fee(&tx, fee_asset_id()),
                Err(MempoolSubmissionError::InvalidFeeAsset { .. })
            );
        }
    }
}
