//! Public pay-to-ID notes holding `USDCx`.

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::note::{Note, NoteType, Nullifier};
use miden_standards::note::{P2idNote, P2idNoteStorage};

/// A public pay-to-ID note holding only the configured `USDCx` asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsdcxP2Id {
    note: Note,
    amount: u64,
    target: AccountId,
}

impl UsdcxP2Id {
    /// Validates a public P2ID note holding only the specified `USDCx` asset.
    pub fn from_note(note: Note, fee_asset_id: AssetId) -> Option<Self> {
        if note.metadata().note_type() != NoteType::Public
            || note.recipient().script().root() != P2idNote::script_root()
            || note.assets().num_assets() != 1
        {
            return None;
        }
        let storage =
            P2idNoteStorage::try_from(note.recipient().storage().to_elements().as_slice()).ok()?;
        let asset = note.assets().iter_fungible().next()?;
        let amount = asset.amount().as_u64();
        if asset.id() != fee_asset_id {
            return None;
        }
        Some(Self { note, amount, target: storage.target() })
    }

    pub fn target(&self) -> AccountId {
        self.target
    }

    pub fn into_note(self) -> Note {
        self.note
    }

    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The amount of `USDCx` held by the note.
    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn nullifier(&self) -> Nullifier {
        self.note.nullifier()
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::note::{NoteAssets, NoteRecipient, PartialNoteMetadata};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_SENDER,
    };
    use miden_standards::note::BurnNote;

    use super::*;

    fn fee_asset_id() -> AssetId {
        AssetId::new_fungible(FungibleAsset::mock_issuer())
    }

    fn target() -> AccountId {
        ACCOUNT_ID_SENDER.try_into().unwrap()
    }

    fn note(faucet: AccountId, note_type: NoteType) -> Note {
        P2idNote::builder()
            .sender(faucet)
            .target(target())
            .asset(FungibleAsset::new(faucet, 5_000).unwrap())
            .note_type(note_type)
            .serial_number(Word::from([1u32; 4]))
            .build()
            .unwrap()
            .into()
    }

    #[test]
    fn a_valid_note_preserves_its_target_amount_and_contents() {
        let note = note(fee_asset_id().faucet_id(), NoteType::Public);
        let parsed = UsdcxP2Id::from_note(note.clone(), fee_asset_id()).unwrap();
        assert_eq!(parsed.target(), target());
        assert_eq!(parsed.amount(), 5_000);
        assert_eq!(parsed.note(), &note);
        assert_eq!(parsed.nullifier(), note.nullifier());
        assert_eq!(parsed.into_note(), note);
    }

    #[test]
    fn a_zero_amount_is_valid() {
        let note = P2idNote::builder()
            .sender(fee_asset_id().faucet_id())
            .target(target())
            .asset(FungibleAsset::new(fee_asset_id().faucet_id(), 0).unwrap())
            .note_type(NoteType::Public)
            .serial_number(Word::from([2u32; 4]))
            .build()
            .unwrap()
            .into();
        let parsed = UsdcxP2Id::from_note(note, fee_asset_id()).unwrap();
        assert_eq!(parsed.amount(), 0);
        assert_eq!(parsed.target(), target());
    }

    #[test]
    fn another_asset_is_rejected() {
        let other = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
        assert_ne!(other, fee_asset_id().faucet_id());
        assert!(UsdcxP2Id::from_note(note(other, NoteType::Public), fee_asset_id()).is_none());
    }

    #[test]
    fn additional_assets_are_rejected() {
        let other = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
        let note = note(fee_asset_id().faucet_id(), NoteType::Public);
        let assets = NoteAssets::new(vec![
            FungibleAsset::new(fee_asset_id().faucet_id(), 5_000).unwrap().into(),
            FungibleAsset::new(other, 100).unwrap().into(),
        ])
        .unwrap();
        let mixed = Note::new(
            assets,
            PartialNoteMetadata::new(target(), NoteType::Public),
            note.recipient().clone(),
        );
        assert!(UsdcxP2Id::from_note(mixed, fee_asset_id()).is_none());
    }

    #[test]
    fn private_notes_are_rejected() {
        assert!(
            UsdcxP2Id::from_note(
                note(fee_asset_id().faucet_id(), NoteType::Private),
                fee_asset_id()
            )
            .is_none()
        );
    }

    #[test]
    fn empty_notes_are_rejected() {
        let note = note(fee_asset_id().faucet_id(), NoteType::Public);
        let empty = Note::new(
            NoteAssets::default(),
            PartialNoteMetadata::new(target(), NoteType::Public),
            note.recipient().clone(),
        );
        assert!(UsdcxP2Id::from_note(empty, fee_asset_id()).is_none());
    }

    #[test]
    fn other_scripts_are_rejected() {
        let note = note(fee_asset_id().faucet_id(), NoteType::Public);
        let recipient = NoteRecipient::new(
            Word::default(),
            BurnNote::script(),
            note.recipient().storage().clone(),
        );
        let other = Note::new(
            note.assets().clone(),
            PartialNoteMetadata::new(target(), NoteType::Public),
            recipient,
        );
        assert!(UsdcxP2Id::from_note(other, fee_asset_id()).is_none());
    }
}
