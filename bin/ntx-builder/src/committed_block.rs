use std::collections::HashMap;

use miden_protocol::account::{AccountId, AccountUpdateDetails};
use miden_protocol::block::{BlockHeader, SignedBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OutputNote, TransactionId};
use miden_standards::note::AccountTargetNetworkNote;

use crate::sponsorship::SponsorshipNote;

/// Network-relevant state extracted from a committed [`SignedBlock`].
///
/// Produced once per committed block on the ntx-builder side. The DB layer applies the contained
/// effects to local state, and the scheduler reads them to resolve its in-flight transactions.
#[derive(Debug, Clone)]
pub struct CommittedBlockEffects {
    pub header: BlockHeader,
    pub network_notes: Vec<AccountTargetNetworkNote>,
    /// `FEE_SPONSORSHIP` notes created by this block. Indexed by feature note id so transaction
    /// selection can include each sponsorship in the same transaction as its feature note.
    pub sponsorship_notes: Vec<SponsorshipNote>,
    pub nullifiers: Vec<Nullifier>,
    pub network_account_updates: Vec<(AccountId, AccountUpdateDetails)>,
    /// Transaction id paired with the account it updated, for every transaction in the block.
    /// `apply_committed_block` uses this to record the latest landed transaction per network
    /// account, and the scheduler uses it to confirm that its own submission landed.
    pub account_transactions: Vec<(AccountId, TransactionId)>,
}

impl CommittedBlockEffects {
    /// Filters the committed block down to the slice the ntx-builder cares about: public network
    /// notes, `FEE_SPONSORSHIP` notes, network-account updates, and all created nullifiers.
    ///
    /// Private output notes cannot be network notes (which must be public) and are skipped. Non-
    /// network output notes and non-network account updates are also dropped. `FEE_SPONSORSHIP`
    /// notes carry no attachments, so they are recognized by script root before the attachment
    /// check that classifies network notes.
    pub fn from_signed_block(block: &SignedBlock) -> Self {
        let header = block.header().clone();
        let body = block.body();

        let mut network_notes = Vec::new();
        let mut sponsorship_notes = Vec::new();
        for batch in body.output_note_batches() {
            for (_idx, output_note) in batch {
                let OutputNote::Public(public) = output_note else {
                    continue;
                };
                if let Ok(sponsorship) = SponsorshipNote::try_from(public.as_note().clone()) {
                    sponsorship_notes.push(sponsorship);
                } else if let Ok(network_note) =
                    AccountTargetNetworkNote::new(public.as_note().clone())
                {
                    network_notes.push(network_note);
                }
            }
        }

        let nullifiers = body.created_nullifiers().to_vec();

        // Public accounts are a superset of network accounts; `apply_committed_block` does the
        // final network-only filtering via `NetworkAccountEffect::from_protocol` (full-state
        // storage check) and a DB lookup for partial deltas.
        let network_account_updates = body
            .updated_accounts()
            .iter()
            .filter_map(|update| {
                let account_id = update.account_id();
                if !account_id.is_public() {
                    return None;
                }
                Some((account_id, update.details().clone()))
            })
            .collect();

        let account_transactions = body
            .transactions()
            .as_slice()
            .iter()
            .map(|tx| (tx.account_id(), tx.id()))
            .collect();

        Self {
            header,
            network_notes,
            sponsorship_notes,
            nullifiers,
            network_account_updates,
            account_transactions,
        }
    }

    /// The latest transaction committed against each account in this block.
    ///
    /// `account_transactions` is in block order, so collecting into a map keeps the last
    /// transaction per account. Both `apply_committed_block` (to persist `accounts.last_tx_id`) and
    /// the scheduler (to detect that a submitted transaction landed) derive landing state from this
    /// single definition, so the two never disagree.
    pub fn latest_tx_per_account(&self) -> HashMap<AccountId, TransactionId> {
        self.account_transactions.iter().copied().collect()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::block::{BlockBody, BlockNumber, BlockSignatures, SignedBlock};
    use miden_protocol::transaction::{OrderedTransactionHeaders, PublicOutputNote};

    use super::*;
    use crate::test_utils::{
        mock_block_header,
        mock_network_account_id,
        mock_single_target_note,
        mock_sponsorship_note,
    };

    /// `FEE_SPONSORSHIP` notes are extracted by script root, everything else keeps going through
    /// the attachment-based network-note classification.
    #[test]
    fn from_signed_block_splits_network_and_sponsorship_notes() {
        let account_id = mock_network_account_id();
        let feature = mock_single_target_note(account_id, 1);
        let sponsorship = mock_sponsorship_note(account_id, feature.as_note().id(), 2);

        let batch = vec![
            (0, OutputNote::Public(PublicOutputNote::new(feature.as_note().clone()).unwrap())),
            (1, OutputNote::Public(PublicOutputNote::new(sponsorship.clone()).unwrap())),
        ];
        let body = BlockBody::new_unchecked(
            Vec::new(),
            vec![batch],
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(Vec::new()),
        );
        let block = SignedBlock::new_unchecked(
            mock_block_header(BlockNumber::from(1)),
            body,
            BlockSignatures::new(Vec::new()).unwrap(),
        );

        let effects = CommittedBlockEffects::from_signed_block(&block);

        assert_eq!(effects.network_notes.len(), 1);
        assert_eq!(effects.network_notes[0].as_note().id(), feature.as_note().id());
        assert_eq!(effects.sponsorship_notes.len(), 1);
        assert_eq!(effects.sponsorship_notes[0].id(), sponsorship.id());
        assert_eq!(effects.sponsorship_notes[0].feature_note_id(), feature.as_note().id());
    }
}
