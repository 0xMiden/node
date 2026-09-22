//! Discovery of the deposits sent to the funding account.
//!
//! An operator refills the funding account by sending it a public pay-to-ID note which holds the
//! native asset. This module finds those notes. The worker can consume one deposit and create
//! queued funding notes in the same transaction.

use anyhow::Result;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteType};
use miden_standards::note::{P2idNote, P2idNoteStorage};

use crate::node::RpcNodeClient;

// DEPOSIT SCANNER
// ================================================================================================

/// Finds the deposits addressed to the funding account.
pub struct DepositScanner {
    /// The funding account the deposits target.
    funder: AccountId,
    /// The native asset of the chain.
    fee_asset_id: AssetId,
    /// The block the next scan starts at.
    next_block: BlockNumber,
}

impl DepositScanner {
    /// Creates a scanner that starts at genesis.
    pub fn new(funder: AccountId, fee_asset_id: AssetId) -> Self {
        Self {
            funder,
            fee_asset_id,
            next_block: BlockNumber::GENESIS,
        }
    }

    /// Returns true after all note pages through `tip` have been checked.
    pub fn is_caught_up(&self, tip: BlockNumber) -> bool {
        self.next_block > tip
    }

    /// Returns one page of deposits. Advances the cursor after all requests succeed.
    pub async fn scan(&mut self, node: &RpcNodeClient, tip: BlockNumber) -> Result<Vec<Note>> {
        if self.is_caught_up(tip) {
            return Ok(Vec::new());
        }

        let synced =
            node.sync_deposits(self.funder, self.fee_asset_id, self.next_block, tip).await?;

        self.next_block = synced.last_checked_block + 1;
        Ok(synced.deposits)
    }
}

// DEPOSIT FILTER
// ================================================================================================

/// Returns `true` when the note is a deposit which `funder` can consume.
///
/// A deposit is a public pay-to-ID note which targets `funder` and holds nothing but the native
/// asset. Only the native asset is collected, because a note holding anything else would put an
/// asset the service cannot spend into the vault.
pub fn is_deposit(note: &Note, funder: AccountId, fee_asset_id: AssetId) -> bool {
    if note.metadata().note_type() != NoteType::Public {
        return false;
    }
    if note.recipient().script().root() != P2idNote::script_root() {
        return false;
    }

    let targets_funder =
        P2idNoteStorage::try_from(note.recipient().storage().to_elements().as_slice())
            .is_ok_and(|storage| storage.target() == funder);
    if !targets_funder {
        return false;
    }

    note.assets().num_assets() == 1 && native_amount(note, fee_asset_id) > 0
}

/// The amount of the native asset the note holds.
pub fn native_amount(note: &Note, fee_asset_id: AssetId) -> u64 {
    note.assets()
        .iter()
        .filter_map(|asset| {
            asset
                .as_fungible()
                .filter(|asset| asset.id() == fee_asset_id)
                .map(|asset| asset.amount().as_u64())
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;

    use super::*;
    use crate::test_utils::genesis_style_wallet;

    /// The native asset in these tests, which the mock faucet issues.
    fn fee_asset_id() -> AssetId {
        AssetId::new_fungible(FungibleAsset::mock_issuer())
    }

    /// Builds a public P2ID note which holds `amount` of `faucet_id` and targets `target`.
    fn deposit_note(
        target: AccountId,
        faucet_id: AccountId,
        amount: u64,
        serial: u32,
        note_type: NoteType,
    ) -> Note {
        P2idNote::builder()
            .sender(target)
            .target(target)
            .asset(FungibleAsset::new(faucet_id, amount).expect("valid asset"))
            .note_type(note_type)
            .serial_number(Word::from([serial; 4]))
            .build()
            .expect("the note should build")
            .into()
    }

    /// A public P2ID note holding the native asset and targeting the funder is a deposit.
    #[test]
    fn a_native_asset_note_for_the_funder_is_a_deposit() {
        let funder = FungibleAsset::mock_issuer();
        let note = deposit_note(funder, funder, 5_000, 1, NoteType::Public);

        assert!(is_deposit(&note, funder, fee_asset_id()));
        assert_eq!(native_amount(&note, fee_asset_id()), 5_000);
    }

    /// Only the native asset is collected: anything else would leave an asset in the vault which
    /// the service cannot spend.
    #[test]
    fn a_note_holding_another_asset_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let (other, _) = genesis_style_wallet(funder, 0, [3; 32]).expect("wallet should build");
        let note = deposit_note(funder, other.id(), 5_000, 2, NoteType::Public);

        assert!(!is_deposit(&note, funder, fee_asset_id()));
        assert_eq!(native_amount(&note, fee_asset_id()), 0);
    }

    /// The note tag only encodes the leading bits of an account ID, so notes for other accounts
    /// reach the scan and must be filtered by their target.
    #[test]
    fn a_note_for_another_account_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let (other, _) = genesis_style_wallet(funder, 0, [5; 32]).expect("wallet should build");
        let note = deposit_note(other.id(), funder, 5_000, 3, NoteType::Public);

        assert!(!is_deposit(&note, funder, fee_asset_id()));
    }

    /// The node stores no details for a private note, so it cannot be consumed.
    #[test]
    fn a_private_note_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let note = deposit_note(funder, funder, 5_000, 4, NoteType::Public);
        let private = deposit_note(funder, funder, 5_000, 4, NoteType::Private);

        assert!(is_deposit(&note, funder, fee_asset_id()));
        assert!(!is_deposit(&private, funder, fee_asset_id()));
    }
}
