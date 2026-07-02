use miden_protocol::account::{AccountId, AccountUpdateDetails};
use miden_protocol::block::{BlockHeader, SignedBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OutputNote, TransactionId};
use miden_standards::note::AccountTargetNetworkNote;

use crate::db::models::account_effect::NetworkAccountEffect;

/// Network-relevant state extracted from a committed [`SignedBlock`].
///
/// Produced once per committed block on the ntx-builder side. Downstream code (DB layer,
/// coordinator) applies the contained effects to local state.
#[derive(Debug, Clone)]
pub struct CommittedBlockEffects {
    pub header: BlockHeader,
    pub network_notes: Vec<AccountTargetNetworkNote>,
    pub nullifiers: Vec<Nullifier>,
    pub network_account_updates: Vec<(AccountId, AccountUpdateDetails)>,
    /// Transaction id paired with the account it updated, for every transaction in the block.
    /// `apply_committed_block` uses this to record the latest landed transaction per network
    /// account so actors can confirm their own submitted transaction landed.
    pub account_transactions: Vec<(AccountId, TransactionId)>,
}

impl CommittedBlockEffects {
    /// Filters the committed block down to the slice the ntx-builder cares about: public network
    /// notes, network-account updates, and all created nullifiers.
    ///
    /// Private output notes cannot be network notes (which must be public) and are skipped. Non-
    /// network output notes and non-network account updates are also dropped.
    pub fn from_signed_block(block: &SignedBlock) -> Self {
        let header = block.header().clone();
        let body = block.body();

        let mut network_notes = Vec::new();
        for batch in body.output_note_batches() {
            for (_idx, output_note) in batch {
                if let OutputNote::Public(public) = output_note
                    && let Ok(network_note) =
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
            nullifiers,
            network_account_updates,
            account_transactions,
        }
    }

    /// Returns the ids of the network accounts created by this block.
    ///
    /// The coordinator uses this to release actor spawns that were deferred until the account's
    /// creation transaction committed.
    pub fn created_network_accounts(&self) -> impl Iterator<Item = AccountId> + '_ {
        self.network_account_updates.iter().filter_map(|(account_id, details)| {
            matches!(
                NetworkAccountEffect::from_protocol(details),
                Some(NetworkAccountEffect::Created(_))
            )
            .then_some(*account_id)
        })
    }
}
