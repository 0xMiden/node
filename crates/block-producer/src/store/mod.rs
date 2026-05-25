use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::num::NonZeroU32;

use itertools::Itertools;
use miden_node_utils::formatting::format_opt;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

// TRANSACTION INPUTS
// ================================================================================================

/// Information needed from the store to verify a transaction.
#[derive(Debug)]
pub struct TransactionInputs {
    /// Account ID
    pub account_id: AccountId,
    /// The account commitment in the store corresponding to tx's account ID
    pub account_commitment: Option<Word>,
    /// Maps each consumed notes' nullifier to block number, where the note is consumed.
    ///
    /// We use `NonZeroU32` as the wire format uses 0 to encode none.
    pub nullifiers: HashMap<Nullifier, Option<NonZeroU32>>,
    /// Unauthenticated note commitments which are present in the store.
    ///
    /// These are notes which were committed _after_ the transaction was created.
    pub found_unauthenticated_notes: HashSet<Word>,
    /// The current block height.
    pub current_block_height: BlockNumber,
}

impl Display for TransactionInputs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|(k, v)| format!("{k}: {}", format_opt(v.as_ref())))
            .join(", ");

        let nullifiers = if nullifiers.is_empty() {
            "None".to_owned()
        } else {
            format!("{{ {nullifiers} }}")
        };

        f.write_fmt(format_args!(
            "{{ account_id: {}, account_commitment: {}, nullifiers: {} }}",
            self.account_id,
            format_opt(self.account_commitment.as_ref()),
            nullifiers
        ))
    }
}
