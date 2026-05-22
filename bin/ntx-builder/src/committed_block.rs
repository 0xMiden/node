use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::{BlockHeader, SignedBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::OutputNote;
use miden_standards::note::AccountTargetNetworkNote;

/// Network-relevant state extracted from a committed [`SignedBlock`].
///
/// Produced once per committed block on the ntx-builder side. Downstream code (DB layer,
/// coordinator) applies the contained effects to local state.
#[derive(Debug, Clone)]
pub struct CommittedBlockEffects {
    pub header: BlockHeader,
    pub network_notes: Vec<AccountTargetNetworkNote>,
    pub nullifiers: Vec<Nullifier>,
    pub network_account_updates: Vec<(NetworkAccountId, AccountUpdateDetails)>,
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

        let network_account_updates = body
            .updated_accounts()
            .iter()
            .filter_map(|update| {
                let network_id = NetworkAccountId::try_from(update.account_id()).ok()?;
                Some((network_id, update.details().clone()))
            })
            .collect();

        Self {
            header,
            network_notes,
            nullifiers,
            network_account_updates,
        }
    }
}
