use std::collections::{HashMap, HashSet};

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OutputNote, TransactionId};
use miden_standards::note::AccountTargetNetworkNote;

use crate::db::queries::account_effect::NetworkAccountEffect;
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
    pub network_account_updates: Vec<(AccountId, NetworkAccountEffect)>,
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

        // A transaction against an empty initial state commitment creates its account. The genesis
        // block has no transactions, but it creates every account it contains.
        let is_genesis = header.block_num() == BlockNumber::GENESIS;
        let new_account_ids = body.transactions().created_account_ids().collect::<HashSet<_>>();

        // Public accounts are a superset of network accounts. `NetworkAccountEffect` filters
        // creations by their storage, and `apply_committed_block` filters updates by a DB lookup.
        let network_account_updates = body
            .updated_accounts()
            .iter()
            .filter_map(|update| {
                let account_id = update.account_id();
                if !account_id.is_public() {
                    return None;
                }
                let effect = if is_genesis || new_account_ids.contains(&account_id) {
                    NetworkAccountEffect::from_account_creation(update.details())
                } else {
                    NetworkAccountEffect::from_account_update(update.details())
                }?;
                Some((account_id, effect))
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
    use anyhow::Context;
    use miden_protocol::Word;
    use miden_protocol::block::{
        BlockAccountUpdate,
        BlockBody,
        BlockNumber,
        BlockSignatures,
        SignedBlock,
    };
    use miden_protocol::transaction::{
        InputNotes,
        OrderedTransactionHeaders,
        PublicOutputNote,
        TransactionHeader,
    };

    use super::*;
    use crate::test_utils::{
        mock_block_header,
        mock_network_account_id,
        mock_network_account_update,
        mock_single_target_note,
        mock_sponsorship_note,
    };

    /// Returns the effect of a committed block with a single transaction against the mock network
    /// account. The account patch carries code, so it has the shape of an account creation and of a
    /// code upgrade.
    fn committed_network_account_effect(
        initial_state_commitment: Word,
    ) -> anyhow::Result<Option<NetworkAccountEffect>> {
        let (account, details) = mock_network_account_update();
        let final_state_commitment = account.to_commitment();
        let update = BlockAccountUpdate::new(account.id(), final_state_commitment, details)?;
        let transaction = TransactionHeader::new(
            account.id(),
            initial_state_commitment,
            final_state_commitment,
            InputNotes::new_unchecked(Vec::new()),
            Vec::new(),
        )?;
        let body = BlockBody::new_unchecked(
            vec![update],
            Vec::new(),
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(vec![transaction]),
        );
        let block = SignedBlock::new_unchecked(
            mock_block_header(BlockNumber::from(1)),
            body,
            BlockSignatures::new(Vec::new())?,
        );

        let effects = CommittedBlockEffects::from_signed_block(&block);

        let effect = effects
            .network_account_updates
            .into_iter()
            .find_map(|(account_id, effect)| (account_id == account.id()).then_some(effect));
        Ok(effect)
    }

    /// A transaction against an empty initial state creates the account. The same patch against an
    /// existing account is a code upgrade and must not replace the account as a creation.
    #[test]
    fn from_signed_block_tells_account_creation_from_code_upgrade() -> anyhow::Result<()> {
        let creation = committed_network_account_effect(Word::empty())?
            .context("the creation of a network account should have an effect")?;
        assert!(matches!(creation, NetworkAccountEffect::Created(_)));

        let upgrade = committed_network_account_effect(Word::from([1u32, 0, 0, 0]))?
            .context("the code upgrade of a public account should have an effect")?;
        assert!(matches!(upgrade, NetworkAccountEffect::Updated(_)));

        Ok(())
    }

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
