use std::collections::HashSet;
use std::sync::Arc;

use miden_node_proto::decode::ConversionResultExt;
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::sequencer;
use miden_objects::{BuildUnchecked, DecodeMessage};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, Nullifier};
use miden_protocol::transaction::{OutputNote, ProvenTransaction, TransactionId, TxAccountUpdate};
use miden_standards::note::TxFeeNote;

use crate::errors::{MempoolSubmissionError, StateConflict};
use crate::store::TransactionInputs;

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

/// A transaction who's proof has been verified, and which has been authenticated against the store.
///
/// Authentication ensures that all nullifiers are unspent, and additionally authenticates some
/// previously unauthenticated input notes.
///
/// This struct is cheap to clone as it uses an Arc for the heavy data.
///
/// Note that this is of course only valid for the chain height of the authentication.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedTransaction {
    inner: Arc<ProvenTransaction>,
    /// The account state provided by the store [inputs](TransactionInputs).
    ///
    /// This does not necessarily have to match the transaction's initial state
    /// as this may still be modified by inflight transactions.
    store_account_state: Option<Word>,
    /// Unauthenticated note commitments that have now been authenticated by committed state,
    /// either through store [inputs](TransactionInputs) or through locally committed mempool
    /// history.
    ///
    /// In other words, notes which were unauthenticated at the time the transaction was proven,
    /// but which have since been committed to, and authenticated by the store.
    notes_authenticated_by_store: HashSet<Word>,
    /// Chain height that the authentication took place at.
    authentication_height: BlockNumber,
}

impl AuthenticatedTransaction {
    /// Verifies the transaction against the inputs, enforcing that all nullifiers are unspent.
    ///
    /// __No__ proof verification is performed. The caller takes responsibility for ensuring
    /// that the proof is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the transaction's nullifiers are marked as spent by the inputs.
    pub fn new_unchecked(
        tx: Arc<ProvenTransaction>,
        inputs: TransactionInputs,
    ) -> Result<AuthenticatedTransaction, StateConflict> {
        let nullifiers_already_spent = tx
            .nullifiers()
            .filter(|nullifier| inputs.nullifiers.get(nullifier).copied().flatten().is_some())
            .collect::<Vec<_>>();
        if !nullifiers_already_spent.is_empty() {
            return Err(StateConflict::NullifiersAlreadyExist(nullifiers_already_spent));
        }

        Ok(AuthenticatedTransaction {
            inner: tx,
            notes_authenticated_by_store: inputs.found_unauthenticated_notes,
            authentication_height: inputs.current_block_height,
            store_account_state: inputs.account_commitment,
        })
    }

    pub fn id(&self) -> TransactionId {
        self.inner.id()
    }

    pub fn account_id(&self) -> AccountId {
        self.inner.account_id()
    }

    pub fn account_update(&self) -> &TxAccountUpdate {
        self.inner.account_update()
    }

    pub fn store_account_state(&self) -> Option<Word> {
        self.store_account_state
    }

    pub fn authentication_height(&self) -> BlockNumber {
        self.authentication_height
    }

    pub fn nullifiers(&self) -> impl Iterator<Item = Nullifier> + '_ {
        self.inner.nullifiers()
    }

    pub fn output_note_ids(&self) -> impl Iterator<Item = Word> + '_ {
        self.inner.output_notes().iter().map(|n| n.id().as_word())
    }

    pub fn output_note_count(&self) -> usize {
        self.inner.output_notes().num_notes()
    }

    /// Returns the public output notes that use the canonical transaction fee script.
    pub fn fee_notes(&self) -> impl Iterator<Item = &Note> + '_ {
        let fee_script_root = TxFeeNote::script_root();

        self.inner.output_notes().iter().filter_map(move |note| match note {
            OutputNote::Public(note) if note.recipient().script().root() == fee_script_root => {
                Some(note.as_note())
            },
            _ => None,
        })
    }

    pub fn input_note_count(&self) -> usize {
        self.inner.input_notes().num_notes() as usize
    }

    /// Returns the IDs of input notes whose authentication is deferred to the batch or block.
    pub fn unauthenticated_input_note_ids(&self) -> impl Iterator<Item = NoteId> + '_ {
        self.inner.unauthenticated_notes().map(miden_protocol::note::NoteHeader::id)
    }

    pub fn reference_block(&self) -> (BlockNumber, Word) {
        (self.inner.ref_block_num(), self.inner.ref_block_commitment())
    }

    /// Note IDs which were unauthenticated in the transaction __and__ which were not authenticated
    /// by the store inputs.
    pub fn unauthenticated_note_ids(&self) -> impl Iterator<Item = Word> + '_ {
        self.inner
            .unauthenticated_notes()
            .map(|h| h.id().as_word())
            .filter(|commitment| !self.notes_authenticated_by_store.contains(commitment))
    }

    pub(crate) fn mark_notes_authenticated(&mut self, notes: impl IntoIterator<Item = Word>) {
        self.notes_authenticated_by_store.extend(notes);
    }

    pub fn proven_transaction(&self) -> Arc<ProvenTransaction> {
        Arc::clone(&self.inner)
    }

    pub fn expires_at(&self) -> BlockNumber {
        self.inner.expiration_block_num()
    }

    pub fn raw_proven_transaction(&self) -> &ProvenTransaction {
        &self.inner
    }
}

// PROTO CONVERSIONS
// ================================================================================================

impl From<AuthenticatedTransaction> for sequencer::AuthenticatedTransaction {
    fn from(value: AuthenticatedTransaction) -> Self {
        Self {
            transaction: Some(value.inner.as_ref().into()),
            store_account_state: value.store_account_state.map(Into::into),
            notes_authenticated_by_store: value
                .notes_authenticated_by_store
                .into_iter()
                .map(Into::into)
                .collect(),
            authentication_height: value.authentication_height.as_u32(),
        }
    }
}

impl TryFrom<sequencer::AuthenticatedTransaction> for AuthenticatedTransaction {
    type Error = ConversionError;

    fn try_from(value: sequencer::AuthenticatedTransaction) -> Result<Self, Self::Error> {
        let inner = value
            .transaction
            .ok_or_else(|| {
                ConversionError::missing_field::<sequencer::AuthenticatedTransaction>("transaction")
            })?
            .decode_fields()
            .context("transaction")?
            .build_unchecked()
            .map_err(ConversionError::new)
            .context("transaction")?;

        let store_account_state = value.store_account_state.map(Word::try_from).transpose()?;

        let notes_authenticated_by_store = value
            .notes_authenticated_by_store
            .into_iter()
            .map(Word::try_from)
            .collect::<Result<HashSet<_>, _>>()?;

        Ok(Self {
            inner: Arc::new(inner),
            store_account_state,
            notes_authenticated_by_store,
            authentication_height: value.authentication_height.into(),
        })
    }
}

#[cfg(test)]
impl AuthenticatedTransaction {
    //! Builder methods intended for easier test setup.

    /// Short-hand for `Self::new` where the input's are setup to match the transaction's initial
    /// account state. This covers the account's initial state and nullifiers being set to unspent.
    pub fn from_inner(inner: ProvenTransaction) -> Self {
        use miden_protocol::Word;

        let store_account_state = match inner.account_update().initial_state_commitment() {
            zero if zero == Word::empty() => None,
            non_zero => Some(non_zero),
        };
        let inputs = TransactionInputs {
            account_id: inner.account_id(),
            account_commitment: store_account_state,
            nullifiers: inner.nullifiers().map(|nullifier| (nullifier, None)).collect(),
            found_unauthenticated_notes: HashSet::default(),
            current_block_height: 0.into(),
        };
        // SAFETY: nullifiers were set to None aka are definitely unspent.
        Self::new_unchecked(Arc::new(inner), inputs).unwrap()
    }

    /// Overrides the authentication height with the given value.
    #[must_use]
    pub fn with_authentication_height(mut self, height: BlockNumber) -> Self {
        self.authentication_height = height;
        self
    }

    /// Overrides the store state with the given value.
    #[must_use]
    pub fn with_store_state(mut self, state: Word) -> Self {
        self.store_account_state = Some(state);
        self
    }

    /// Unsets the store state.
    #[must_use]
    pub fn with_empty_store_state(mut self) -> Self {
        self.store_account_state = None;
        self
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::Word;
    use miden_protocol::asset::{Asset, AssetId, FungibleAsset};
    use miden_protocol::note::{Note, NoteAssets};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
    use miden_protocol::transaction::{OutputNote, ProvenTransaction, PublicOutputNote};
    use miden_standards::note::TxFeeNote;

    use super::{AuthenticatedTransaction, ensure_transaction_has_fee};
    use crate::errors::MempoolSubmissionError;
    use crate::test_utils::{MockProvenTxBuilder, mock_account_id};

    #[test]
    fn authenticated_transaction_proto_roundtrip_preserves_the_transaction() {
        let transaction = AuthenticatedTransaction::from_inner(
            MockProvenTxBuilder::with_account_index(1).build(),
        );
        let encoded = miden_node_proto::generated::sequencer::AuthenticatedTransaction::from(
            transaction.clone(),
        );
        let decoded = AuthenticatedTransaction::try_from(encoded).unwrap();
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
