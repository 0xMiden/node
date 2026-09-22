//! Discovery of the deposits sent to the funding account.
//!
//! An operator refills the funding account by sending it a public pay-to-ID note which holds the
//! native asset. This module finds those notes. It submits nothing: the worker consumes the
//! deposits it finds as the input notes of the next funding transaction.

use anyhow::Result;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_standards::note::{P2idNote, P2idNoteStorage};

use crate::node::RpcNodeClient;

// DEPOSIT SCANNER
// ================================================================================================

/// Finds the deposits addressed to the funding account.
pub struct DepositScanner {
    /// The funding account the deposits target.
    funder: AccountId,
    /// The faucet which issues the chain's native asset.
    fee_faucet_id: AccountId,
    /// The block the next scan starts at.
    next_block: BlockNumber,
}

impl DepositScanner {
    /// Creates a scanner which starts at the genesis block.
    ///
    /// The scanner keeps no state on disk, so a restart scans the chain again from genesis. A
    /// deposit which is already spent is dropped by the scan, so a rescan finds only the deposits
    /// which are still there.
    pub fn new(funder: AccountId, fee_faucet_id: AccountId) -> Self {
        Self {
            funder,
            fee_faucet_id,
            next_block: BlockNumber::GENESIS,
        }
    }

    /// Returns the deposits committed after the previous scan up to `to_block`, which are unspent
    /// at `to_block`.
    ///
    /// The cursor advances past `to_block` only when every request of the scan succeeds, so a
    /// failed scan covers the same range again. A successful scan advances the cursor whether or not
    /// the caller consumes what it returns. The caller holds every deposit it is given until the
    /// deposit is spent, so a range is never scanned twice.
    pub async fn scan(&mut self, node: &RpcNodeClient, to_block: BlockNumber) -> Result<Vec<Note>> {
        let from_block = self.next_block;
        // A previous scan already covered `to_block`.
        if from_block > to_block {
            return Ok(Vec::new());
        }

        let tag = NoteTag::with_account_target(self.funder);
        let note_ids = node.sync_note_ids(tag, from_block, to_block).await?;

        let candidates: Vec<Note> = node
            .get_public_notes_by_id(&note_ids)
            .await?
            .into_iter()
            .filter(|note| is_deposit(note, self.funder, self.fee_faucet_id))
            .collect();

        let nullifiers: Vec<_> = candidates.iter().map(Note::nullifier).collect();
        let spent = node.sync_nullifiers(&nullifiers, from_block, to_block).await?;

        self.next_block = to_block + 1;

        Ok(candidates
            .into_iter()
            .filter(|note| !spent.contains(&note.nullifier()))
            .collect())
    }
}

// DEPOSIT FILTER
// ================================================================================================

/// Returns `true` when the note is a deposit which `funder` can consume.
///
/// A deposit is a public pay-to-ID note which targets `funder` and holds nothing but the native
/// asset. Only the native asset is collected, because a note holding anything else would put an
/// asset the service cannot spend into the vault.
pub fn is_deposit(note: &Note, funder: AccountId, fee_faucet_id: AccountId) -> bool {
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

    note.assets().num_assets() == 1 && native_amount(note, fee_faucet_id) > 0
}

/// The amount of the native asset the note holds.
pub fn native_amount(note: &Note, fee_faucet_id: AccountId) -> u64 {
    note.assets()
        .iter()
        .filter_map(|asset| {
            asset
                .as_fungible()
                .filter(|asset| asset.faucet_id() == fee_faucet_id)
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

        assert!(is_deposit(&note, funder, funder));
        assert_eq!(native_amount(&note, funder), 5_000);
    }

    /// Only the native asset is collected: anything else would leave an asset in the vault which
    /// the service cannot spend.
    #[test]
    fn a_note_holding_another_asset_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let (other, _) = genesis_style_wallet(funder, 0, [3; 32]).expect("wallet should build");
        let note = deposit_note(funder, other.id(), 5_000, 2, NoteType::Public);

        assert!(!is_deposit(&note, funder, funder));
        assert_eq!(native_amount(&note, funder), 0);
    }

    /// The note tag only encodes the leading bits of an account ID, so notes for other accounts
    /// reach the scan and must be filtered by their target.
    #[test]
    fn a_note_for_another_account_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let (other, _) = genesis_style_wallet(funder, 0, [5; 32]).expect("wallet should build");
        let note = deposit_note(other.id(), funder, 5_000, 3, NoteType::Public);

        assert!(!is_deposit(&note, funder, funder));
    }

    /// The node stores no details for a private note, so it cannot be consumed.
    #[test]
    fn a_private_note_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let note = deposit_note(funder, funder, 5_000, 4, NoteType::Public);
        let private = deposit_note(funder, funder, 5_000, 4, NoteType::Private);

        assert!(is_deposit(&note, funder, funder));
        assert!(!is_deposit(&private, funder, funder));
    }
}
