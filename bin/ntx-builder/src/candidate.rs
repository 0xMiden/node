use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::asset::{Asset, AssetAmount};
use miden_protocol::block::BlockHeader;
use miden_protocol::note::{Note, NoteId, Nullifier};
use miden_protocol::transaction::PartialBlockchain;
use miden_standards::note::AccountTargetNetworkNote;

// SPONSORED FEATURE NOTE
// ================================================================================================

/// A feature note bundled with the `FEE_SPONSORSHIP` notes that pay its fee.
///
/// Transaction selection packs a bundle as a unit because a sponsorship note may only be consumed
/// with its feature note. Consumability filtering may retain a valid subset: a feature can execute
/// without every selected sponsorship when its required fee is otherwise covered. A bundle with no
/// sponsorships is a plain network note.
#[derive(Clone, Debug)]
pub struct SponsoredFeatureNote {
    /// The network note targeted at the account.
    pub feature: AccountTargetNetworkNote,
    /// `FEE_SPONSORSHIP` notes bound to the feature note, consumed in the same transaction.
    pub sponsorships: Vec<Note>,
}

impl SponsoredFeatureNote {
    /// Number of notes the bundle contributes to a transaction: the feature note plus its
    /// sponsorships.
    pub fn num_notes(&self) -> usize {
        1 + self.sponsorships.len()
    }

    /// Retains only sponsorships carrying the fee asset accepted by the network account.
    ///
    /// This must run before applying the per-feature sponsorship cap so notes carrying an
    /// unrelated asset cannot crowd valid sponsorships out of the candidate.
    pub fn retain_sponsorships_for_fee_asset(&mut self, fee_asset_id: Word) {
        self.sponsorships.retain(|note| {
            note.assets()
                .as_slice()
                .first()
                .is_some_and(|asset| asset.id().to_word() == fee_asset_id)
        });
    }

    /// Orders sponsorships by descending amount so that the per-feature cap keeps the most
    /// valuable ones.
    ///
    /// The builder cannot know the fee before executing, so it cannot pick the smallest sufficient
    /// sponsorship; keeping the largest maximizes the chance the feature note's fee is covered.
    /// Without an ordering, the cap truncates in the arbitrary order the database returned, and a
    /// spray of dust sponsorships could occupy every slot and starve the one that actually pays.
    ///
    /// Run this after [`Self::retain_sponsorships_for_fee_asset`]: only then is every remaining
    /// note issued by the same faucet, which is what makes the amounts comparable. Sponsorships
    /// carrying no fungible amount sort last.
    pub fn sort_sponsorships_by_amount(&mut self) {
        self.sponsorships.sort_by_key(|note| Reverse(sponsorship_amount(note)));
    }
}

/// Returns the fungible amount a sponsorship note carries, or [`AssetAmount::ZERO`] if it carries
/// no fungible asset.
///
/// A sponsorship note is validated to carry exactly one asset when it is ingested, so the first
/// asset is the fee it pays.
fn sponsorship_amount(note: &Note) -> AssetAmount {
    match note.assets().as_slice().first() {
        Some(Asset::Fungible(asset)) => asset.amount(),
        _ => AssetAmount::ZERO,
    }
}

// TRANSACTION CANDIDATE
// ================================================================================================

/// A candidate network transaction.
///
/// Contains the data pertaining to a specific network account which can be used to build a network
/// transaction.
#[derive(Clone, Debug)]
pub struct TransactionCandidate {
    /// The current inflight state of the account.
    ///
    /// Wrapped in `Arc` so building a candidate shares the account the attempt loaded instead of
    /// deep-cloning it, which is expensive for accounts with large storage maps. The account is
    /// only ever read during execution.
    pub account: Arc<Account>,

    /// The sponsored feature notes selected for this transaction: each feature note addressed to
    /// the account together with the sponsorships that pay its fee.
    pub notes: Vec<SponsoredFeatureNote>,

    /// The latest locally committed block header.
    ///
    /// This should be used as the reference block during transaction execution.
    pub chain_tip_header: BlockHeader,

    /// The chain MMR, which lags behind the tip by one block.
    ///
    /// Wrapped in `Arc` to avoid expensive clones when reading the chain state.
    pub chain_mmr: Arc<PartialBlockchain>,
}

impl TransactionCandidate {
    /// Total number of notes across all bundles.
    pub fn num_notes(&self) -> usize {
        self.notes.iter().map(SponsoredFeatureNote::num_notes).sum()
    }

    /// Maps each sponsorship note id to the nullifier of the feature note it sponsors.
    ///
    /// Sponsorship notes have no row in the `notes` table, so any failure of a sponsorship is
    /// attributed to (and penalizes) the feature note of its bundle. Feature notes are absent from
    /// the map: their failures are recorded under their own nullifier.
    pub fn sponsor_to_feature_nullifier(&self) -> HashMap<NoteId, Nullifier> {
        self.notes
            .iter()
            .flat_map(|sponsored| {
                let feature_nullifier = sponsored.feature.as_note().nullifier();
                sponsored
                    .sponsorships
                    .iter()
                    .map(move |sponsorship| (sponsorship.id(), feature_nullifier))
            })
            .collect()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        mock_network_account_id,
        mock_single_target_note,
        mock_sponsorship_note,
        mock_sponsorship_note_with_amount,
    };

    /// Builds one feature note bundled with `num_sponsorships` sponsorships bound to it.
    fn sponsored(feature_seed: u8, num_sponsorships: u8) -> SponsoredFeatureNote {
        let account_id = mock_network_account_id();
        let feature = mock_single_target_note(account_id, feature_seed);
        let sponsorships = (0..num_sponsorships)
            .map(|i| {
                mock_sponsorship_note(account_id, feature.as_note().id(), feature_seed + 100 + i)
            })
            .collect();
        SponsoredFeatureNote { feature, sponsorships }
    }

    /// The failure-attribution map names every sponsorship and no feature note.
    #[test]
    fn sponsor_to_feature_nullifier_covers_sponsorships_only() {
        let sponsored_notes = [sponsored(1, 2), sponsored(2, 0)];
        let chain_mmr = PartialBlockchain::new(
            miden_protocol::crypto::merkle::mmr::PartialMmr::from_peaks(
                miden_protocol::crypto::merkle::mmr::MmrPeaks::new(
                    miden_protocol::crypto::merkle::mmr::Forest::new(0).unwrap(),
                    vec![],
                )
                .unwrap(),
            ),
            [],
        )
        .unwrap();
        let candidate = TransactionCandidate {
            account: Arc::new(crate::test_utils::mock_account(mock_network_account_id())),
            notes: sponsored_notes.to_vec(),
            chain_tip_header: crate::test_utils::mock_block_header(0_u32.into()),
            chain_mmr: Arc::new(chain_mmr),
        };

        let map = candidate.sponsor_to_feature_nullifier();
        assert_eq!(map.len(), 2);
        let feature_nullifier = sponsored_notes[0].feature.as_note().nullifier();
        for sponsorship in &sponsored_notes[0].sponsorships {
            assert_eq!(map[&sponsorship.id()], feature_nullifier);
        }
        assert_eq!(candidate.num_notes(), 4);
    }

    /// Sponsorships are ordered largest-first, so a later truncation to the cap keeps the ones most
    /// likely to cover the fee rather than whatever the database returned first.
    #[test]
    fn sort_sponsorships_by_amount_orders_largest_first() {
        let account_id = mock_network_account_id();
        let feature = mock_single_target_note(account_id, 1);
        let feature_id = feature.as_note().id();
        let sponsorships = vec![
            mock_sponsorship_note_with_amount(account_id, feature_id, 2, 5),
            mock_sponsorship_note_with_amount(account_id, feature_id, 3, 500),
            mock_sponsorship_note_with_amount(account_id, feature_id, 4, 50),
        ];
        let mut sponsored = SponsoredFeatureNote { feature, sponsorships };

        sponsored.sort_sponsorships_by_amount();

        let amounts = sponsored
            .sponsorships
            .iter()
            .map(|note| sponsorship_amount(note).as_u64())
            .collect::<Vec<_>>();
        assert_eq!(amounts, [500, 50, 5]);
    }
}
