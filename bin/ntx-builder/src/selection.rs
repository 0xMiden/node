//! Transaction selection for a single network account.
//!
//! Selection is a pure read: it queries the account's available notes, drops the notes whose script
//! root the account does not allowlist, attaches each remaining feature note's pending
//! sponsorships, and packs the resulting bundles into a [`TransactionCandidate`] under the per-
//! transaction note budget. The notes it drops are returned to the caller rather than written,
//! because a transaction attempt never writes to the database.

use std::collections::{HashMap, HashSet};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;

use anyhow::Context;
use miden_node_tracing::{ErrorReport, info, warn};
use miden_node_utils::formatting::format_opt;
use miden_protocol::account::Account;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::TransactionArgs;
use miden_standards::account::fees::FeePolicyManager;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_tx::FailedNote;

use crate::allowlist::{NoteScriptNotAllowlisted, partition_by_allowlist};
use crate::candidate::{SponsoredFeatureNote, TransactionCandidate};
use crate::chain_state::ChainState;
use crate::db::NtxDbReader;
use crate::{LOG_TARGET, NoteError};

/// Maximum number of `FEE_SPONSORSHIP` notes attached to a single feature note. A feature note with
/// more pending sponsorships than this keeps a subset of this size.
const MAX_SPONSORSHIPS_PER_NOTE: usize = 3;

/// Builds the [`TransactionArgs`] shared by every network transaction.
///
/// Currently these attach the canonical [`ExpirationTransactionScript`] for `expiration_delta`
/// blocks, with the script paired to the `TX_SCRIPT_ARGS` word it reads its delta from.
///
/// The script itself is account-independent and its MAST root is identical for every delta (the
/// delta travels in the args word, not the code), so the builder derives these once at startup and
/// shares them across all attempts. The matching root
/// ([`ExpirationTransactionScript::script_root`]) is what network accounts must allowlist for these
/// transactions to be accepted on-chain.
pub(crate) fn build_tx_args(expiration_delta: NonZeroU16) -> TransactionArgs {
    let script = ExpirationTransactionScript::new(expiration_delta);
    TransactionArgs::default().with_tx_script_and_args(script.into(), script.tx_script_args())
}

// SELECTION
// ================================================================================================

/// The outcome of selecting notes for one account.
pub(crate) struct Selection {
    /// The candidate transaction, or `None` when no bundle was selected.
    pub candidate: Option<TransactionCandidate>,
    /// Notes dropped because the account does not allowlist their script root. They can never be
    /// consumed by this account, so the caller must penalize them.
    pub rejected: Vec<(Nullifier, NoteError)>,
    /// Notes whose stored eligibility block has passed while the exact hint and backoff check still
    /// rejects them, paired with the block they really become eligible at. The caller persists
    /// these; see [`crate::db::eligibility`].
    pub stale_eligibility: Vec<(Nullifier, BlockNumber)>,
}

/// Selects a transaction candidate for `account` by querying its available notes.
///
/// `chain_state` fixes the reference block for the whole attempt, so the candidate, the eligibility
/// filtering and the later execution all agree on one chain tip.
pub(crate) async fn select_candidate(
    db: &NtxDbReader,
    account: &Arc<Account>,
    chain_state: ChainState,
    max_notes_per_tx: NonZeroUsize,
    max_note_attempts: usize,
) -> anyhow::Result<Selection> {
    let account_id = account.id();
    let block_num = chain_state.chain_tip_header.block_num();
    let max_notes = max_notes_per_tx.get();

    let availability = db
        .available_notes(account_id, block_num, max_note_attempts)
        .await
        .context("failed to query DB for available notes")?;
    let stale_eligibility = availability.stale_eligibility;

    let partitioned_notes = partition_by_allowlist(account.as_ref(), availability.eligible)
        .context("failed to read network account note allowlist")?;

    let rejected = partitioned_notes
        .rejected
        .into_iter()
        .map(|(nullifier, script_root)| {
            let error: NoteError = Arc::new(NoteScriptNotAllowlisted::new(script_root));
            (nullifier, error)
        })
        .collect::<Vec<_>>();
    if !rejected.is_empty() {
        info!(
            target: LOG_TARGET,
            "dropping network notes whose script roots are not allowlisted",
            account.id = account_id,
            note.rejected.count = rejected.len()
        );
    }

    // Attach each feature note's pending sponsorships: the bundle is the atomic selection unit,
    // since a sponsorship may only be consumed alongside its feature note.
    let mut sponsorships = if partitioned_notes.allowed.is_empty() {
        HashMap::new()
    } else {
        db.sponsorships_for_pending_notes(account_id)
            .await
            .context("failed to query DB for pending sponsorships")?
    };
    // A bundle must leave room for its feature note within the per-tx note budget.
    let max_sponsorships = MAX_SPONSORSHIPS_PER_NOTE.min(max_notes - 1);
    let fee_asset_id = account
        .storage()
        .get_item(FeePolicyManager::fee_asset_id_slot())
        .context("failed to read network account fee asset ID")?;

    let mut selected: Vec<SponsoredFeatureNote> = Vec::new();
    let mut selected_notes = 0_usize;
    for feature in partitioned_notes.allowed {
        let bundled_sponsorships = sponsorships.remove(&feature.as_note().id()).unwrap_or_default();
        let mut sponsored = SponsoredFeatureNote {
            feature,
            sponsorships: bundled_sponsorships,
        };
        // Filter before applying the cap so assets the account does not accept cannot occupy the
        // limited sponsorship slots, then order by amount so the cap keeps the sponsorships most
        // likely to cover the fee.
        sponsored.retain_sponsorships_for_fee_asset(fee_asset_id);
        sponsored.sort_sponsorships_by_amount();
        sponsored.sponsorships.truncate(max_sponsorships);
        // Bundle-atomic packing: a bundle that does not fit the remaining budget is skipped as a
        // whole (never split) and re-selected in a later round.
        if selected_notes + sponsored.num_notes() > max_notes {
            continue;
        }
        selected_notes += sponsored.num_notes();
        selected.push(sponsored);
    }

    if selected.is_empty() {
        return Ok(Selection {
            candidate: None,
            rejected,
            stale_eligibility,
        });
    }

    let (chain_tip_header, chain_mmr) = chain_state.into_parts();
    Ok(Selection {
        candidate: Some(TransactionCandidate {
            // Cheap: bumps the `Arc` refcount instead of deep-copying the account/storage.
            account: Arc::clone(account),
            notes: selected,
            chain_tip_header,
            chain_mmr,
        }),
        rejected,
        stale_eligibility,
    })
}

// FAILURE ATTRIBUTION
// ================================================================================================

/// Logs each failed note and returns `(nullifier, error)` pairs keyed by the nullifier the failure
/// is recorded under: a feature note fails under its own nullifier, while a sponsorship's failure
/// is charged to the feature note of its bundle (sponsorship notes have no row in the `notes`
/// table). Multiple failures attributed to the same feature note collapse to a single entry, so a
/// bundle never burns more than one attempt per round.
pub(crate) fn attribute_failed_notes(
    failed: Vec<FailedNote>,
    sponsor_to_feature: &HashMap<NoteId, Nullifier>,
) -> Vec<(Nullifier, NoteError)> {
    let mut seen = HashSet::new();
    let mut attributed = Vec::new();
    for f in failed {
        let error_msg = f.error().as_report();
        info!(
            f.error(),
            target: LOG_TARGET,
            "note failed: consumability check",
            note.id = f.note().id(),
            note.nullifier = f.note().nullifier()
        );
        let nullifier = sponsor_to_feature
            .get(&f.note().id())
            .copied()
            .unwrap_or_else(|| f.note().nullifier());
        if seen.insert(nullifier) {
            let error: NoteError = Arc::new(std::io::Error::other(error_msg));
            attributed.push((nullifier, error));
        }
    }
    attributed
}

/// Logs each note discarded for exceeding the per-tx cycle budget on its own and returns their
/// nullifiers.
///
/// These notes were confirmed (by an isolation re-check in `filter_notes`) to need more than the
/// entire per-tx cycle budget for themselves, so they can never be consumed and are marked
/// permanently unconsumable rather than retried.
pub(crate) fn log_oversized_notes(oversized: Vec<FailedNote>) -> Vec<Nullifier> {
    oversized
        .into_iter()
        .map(|note| {
            warn!(
                target: LOG_TARGET,
                "note discarded: exceeds the per-tx cycle budget on its own and can never be consumed",
                note.id = note.note().id(),
                note.nullifier = note.note().nullifier(),
                note.execution_cycles = format_opt(note.num_cycles().as_ref())
            );
            note.note().nullifier()
        })
        .collect()
}

/// Logs each note deferred because the combined per-tx cycle budget was exhausted.
///
/// These notes are individually consumable and are intentionally *not* penalized (no
/// `(nullifier, error)` pairs are returned), so they remain eligible for selection in a subsequent
/// round with their `attempt_count` untouched.
pub(crate) fn log_deferred_notes(deferred: Vec<FailedNote>) {
    for note in deferred {
        info!(
            target: LOG_TARGET,
            "note deferred: exceeded per-tx cycle budget, will retry next round",
            note.id = note.note().id(),
            note.nullifier = note.note().nullifier(),
            note.execution_cycles = format_opt(note.num_cycles().as_ref())
        );
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountId;
    use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};

    use super::*;
    use crate::sponsorship::SponsorshipNote;
    use crate::test_utils::{
        mock_block_header,
        mock_network_account_update,
        mock_single_target_note,
        mock_single_target_note_with_code,
        mock_sponsorship,
        mock_sponsorship_note_with_faucet_and_amount,
        mock_sponsorship_with_amount,
        mock_transaction_id,
    };

    /// A note script the mock network account does not allowlist.
    const OTHER_NOTE_SCRIPT: &str = "\
@note_script
pub proc main
    push.1 drop
end";

    /// A chain state at the genesis block, which is all selection needs from the chain.
    fn test_chain_state() -> ChainState {
        let mmr = PartialMmr::from_peaks(
            MmrPeaks::new(Forest::new(0).expect("forest 0 is valid"), vec![]).unwrap(),
        );
        ChainState::new(mock_block_header(0_u32.into()), mmr)
    }

    /// Seeds a committed network account (with a populated allowlist) and returns its id together
    /// with the account itself.
    async fn seed_selection_account(db: &crate::db::NtxDbWriter) -> (AccountId, Arc<Account>) {
        let (account, _) = mock_network_account_update();
        db.upsert_account_for_test(account.id(), account.clone(), mock_transaction_id(1))
            .await
            .unwrap();
        (account.id(), Arc::new(account))
    }

    /// Runs selection with a 20-note budget, which is the production default.
    async fn select(
        db: &crate::db::NtxDbWriter,
        account: &Arc<Account>,
        max_notes: usize,
    ) -> Selection {
        select_candidate(
            &db.reader(),
            account,
            test_chain_state(),
            NonZeroUsize::new(max_notes).unwrap(),
            30,
        )
        .await
        .unwrap()
    }

    /// Each selected bundle carries exactly the pending sponsorships of its feature note.
    #[tokio::test]
    async fn select_candidate_attaches_sponsorships_for_pending_notes() {
        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        let feature_a = mock_single_target_note(account_id, 1);
        let feature_b = mock_single_target_note(account_id, 2);
        db.insert_network_notes(vec![feature_a.clone(), feature_b.clone()])
            .await
            .unwrap();
        db.insert_sponsorship_notes(vec![
            mock_sponsorship(account_id, feature_a.as_note().id(), 3),
            mock_sponsorship(account_id, feature_a.as_note().id(), 4),
        ])
        .await
        .unwrap();

        let candidate = select(&db, &account, 20).await.candidate.expect("both bundles are viable");

        assert_eq!(candidate.notes.len(), 2);
        for sponsored in &candidate.notes {
            if sponsored.feature.as_note().id() == feature_a.as_note().id() {
                assert_eq!(sponsored.sponsorships.len(), 2, "feature A carries its sponsorships");
            } else {
                assert!(sponsored.sponsorships.is_empty(), "feature B has no sponsorships");
            }
        }
    }

    /// A feature note with more pending sponsorships than the cap gets exactly the cap, and the
    /// slots go to the largest sponsorships.
    #[tokio::test]
    async fn select_candidate_caps_sponsorships_per_note() {
        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        let feature = mock_single_target_note(account_id, 1);
        db.insert_network_notes(vec![feature.clone()]).await.unwrap();
        db.insert_sponsorship_notes(
            (0..5)
                .map(|i| {
                    mock_sponsorship_with_amount(
                        account_id,
                        feature.as_note().id(),
                        10 + i,
                        u64::from(i + 1) * 100,
                    )
                })
                .collect(),
        )
        .await
        .unwrap();

        let candidate = select(&db, &account, 20).await.candidate.expect("the bundle is viable");

        assert_eq!(candidate.notes.len(), 1);
        assert_eq!(candidate.notes[0].sponsorships.len(), MAX_SPONSORSHIPS_PER_NOTE);
        // The five pending sponsorships carry 100 through 500; the cap keeps the largest three.
        let amounts = candidate.notes[0]
            .sponsorships
            .iter()
            .map(|note| note.assets().as_slice()[0].unwrap_fungible().amount().as_u64())
            .collect::<Vec<_>>();
        assert_eq!(amounts, [500, 400, 300]);
    }

    /// Sponsorships carrying the wrong asset are removed before the cap is applied, so they cannot
    /// occupy slots that could hold valid sponsorships.
    #[tokio::test]
    async fn select_candidate_filters_wrong_fee_asset_before_cap() {
        use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;

        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        let feature = mock_single_target_note(account_id, 1);
        let feature_id = feature.as_note().id();
        let valid = mock_sponsorship_with_amount(account_id, feature_id, 2, 100);
        let wrong_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
        let invalid = (3..=5)
            .map(|seed| {
                SponsorshipNote::try_from(mock_sponsorship_note_with_faucet_and_amount(
                    account_id,
                    feature_id,
                    seed,
                    wrong_faucet,
                    u64::from(seed) * 10_000,
                ))
                .expect("wrong-asset sponsorship is structurally valid")
            })
            .collect::<Vec<_>>();

        db.insert_network_notes(vec![feature]).await.unwrap();
        db.insert_sponsorship_notes(std::iter::once(valid.clone()).chain(invalid).collect())
            .await
            .unwrap();

        let candidate = select(&db, &account, 20)
            .await
            .candidate
            .expect("the feature and its valid sponsorship are viable");

        assert_eq!(candidate.notes.len(), 1);
        assert_eq!(candidate.notes[0].sponsorships.len(), 1);
        assert_eq!(candidate.notes[0].sponsorships[0].id(), valid.id());
    }

    /// Bundles are packed atomically against the per-tx note budget: a bundle that does not fit is
    /// skipped as a whole, never split.
    #[tokio::test]
    async fn select_candidate_packs_bundles_atomically() {
        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        // Bundle A is three notes (feature + 2 sponsorships), bundle B is two: only one of them
        // fits a three-note budget.
        let feature_a = mock_single_target_note(account_id, 1);
        let feature_b = mock_single_target_note(account_id, 2);
        db.insert_network_notes(vec![feature_a.clone(), feature_b.clone()])
            .await
            .unwrap();
        db.insert_sponsorship_notes(vec![
            mock_sponsorship(account_id, feature_a.as_note().id(), 3),
            mock_sponsorship(account_id, feature_a.as_note().id(), 4),
            mock_sponsorship(account_id, feature_b.as_note().id(), 5),
        ])
        .await
        .unwrap();

        let candidate = select(&db, &account, 3)
            .await
            .candidate
            .expect("at least one bundle fits the budget");

        assert_eq!(candidate.notes.len(), 1, "only one whole bundle fits three note slots");
        assert!(candidate.num_notes() <= 3, "a bundle must never be split to fit");
        let sponsored = &candidate.notes[0];
        assert!(!sponsored.sponsorships.is_empty(), "the selected bundle keeps its sponsorships");
    }

    /// A note whose script root the account does not allowlist is reported as rejected instead of
    /// being selected, and selection asks for a re-check on the next block so the account is not
    /// reported as idle while the rejected note ages through its attempt budget.
    #[tokio::test]
    async fn select_candidate_reports_notes_outside_the_allowlist() {
        let (db, _dir) = crate::db::test_setup().await;
        let (account_id, account) = seed_selection_account(&db).await;

        // The mock account allowlists the default note script only, so a note with custom code has
        // a script root outside the allowlist.
        let note = mock_single_target_note_with_code(account_id, 7, Some(OTHER_NOTE_SCRIPT));
        db.insert_network_notes(vec![note.clone()]).await.unwrap();

        let selection = select(&db, &account, 20).await;

        assert!(selection.candidate.is_none(), "a non-allowlisted note is never selected");
        assert_eq!(selection.rejected.len(), 1, "the note is reported for the caller to penalize");
        assert_eq!(selection.rejected[0].0, note.as_note().nullifier());
        assert!(
            selection.stale_eligibility.is_empty(),
            "the note was eligible; penalizing it is what moves its eligibility",
        );
    }

    /// The canonical expiration script carries its delta in `TX_SCRIPT_ARGS`, so every delta shares
    /// a single script root (the one network accounts allowlist), while the args word encodes the
    /// delta in its first element.
    #[test]
    fn expiration_script_shares_root_and_encodes_delta_in_args() {
        let one = build_tx_args(NonZeroU16::new(1).unwrap());
        let thirty = build_tx_args(NonZeroU16::new(30).unwrap());
        let max = build_tx_args(NonZeroU16::MAX);

        // All deltas resolve to the single allowlistable root.
        let root = ExpirationTransactionScript::script_root();
        assert_eq!(one.tx_script().unwrap().root(), root);
        assert_eq!(thirty.tx_script().unwrap().root(), root);
        assert_eq!(max.tx_script().unwrap().root(), root);

        // The delta rides in the first element of the args word.
        assert_eq!(one.tx_script_args()[0], Felt::from(1_u16));
        assert_eq!(thirty.tx_script_args()[0], Felt::from(30_u16));
        assert_eq!(max.tx_script_args()[0], Felt::from(u16::MAX));
    }
}
