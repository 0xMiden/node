//! Database query functions for the NTX builder.

use std::collections::HashSet;

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::crypto::merkle::mmr::PartialMmr;

use super::account_effect::NetworkAccountEffect;
use crate::committed_block::CommittedBlockEffects;

mod accounts;
pub use accounts::*;

mod chain_state;
pub use chain_state::*;

mod note_scripts;
pub use note_scripts::*;

mod notes;
pub use notes::*;

#[cfg(test)]
mod tests;

// COMMITTED BLOCK APPLICATION
// ================================================================================================

/// Applies a committed block's effects to the database in a single transaction:
///
/// - Upserts each touched network account: new full-state deltas insert, partial deltas apply to
///   the existing committed row.
/// - Inserts each network note (`INSERT OR IGNORE` to tolerate redeliveries).
/// - Marks any of our pending notes whose nullifiers appear in this block as `committed_at =
///   block_num`, preserving the row so the `GetNetworkNoteStatus` endpoint can report the full
///   lifecycle.
/// - Upserts the singleton `chain_state` row with the new block header and the post-application
///   chain MMR.
///
/// Returns the set of network accounts that were touched by this block (account-state updates or
/// notes targeting the account).
pub fn apply_committed_block(
    conn: &mut SqliteConnection,
    effects: &CommittedBlockEffects,
    chain_mmr: &PartialMmr,
) -> Result<Vec<NetworkAccountId>, DatabaseError> {
    let mut affected_accounts: HashSet<NetworkAccountId> = HashSet::new();

    for (network_id, details) in &effects.network_account_updates {
        let Some(effect) = NetworkAccountEffect::from_protocol(details) else {
            continue;
        };
        match effect {
            NetworkAccountEffect::Created(account) => {
                upsert_account(conn, *network_id, &account)?;
            },
            NetworkAccountEffect::Updated(delta) => {
                // Partial deltas carry no storage to verify network-ness. If the account is not
                // already tracked locally, treat the update as a non-network public account that
                // leaked through the upstream filter and skip it.
                let Some(mut current) = get_account(conn, *network_id)? else {
                    continue;
                };
                current
                    .apply_delta(&delta)
                    .expect("network account delta should apply since the block was committed");
                upsert_account(conn, *network_id, &current)?;
            },
        }
        affected_accounts.insert(*network_id);
    }

    for note in &effects.network_notes {
        let target = NetworkAccountId::new_unchecked(note.target_account_id());
        affected_accounts.insert(target);
    }
    insert_network_notes(conn, &effects.network_notes)?;

    mark_notes_consumed(conn, &effects.nullifiers, effects.header.block_num())?;

    upsert_chain_state(conn, effects.header.block_num(), &effects.header, chain_mmr)?;

    Ok(affected_accounts.into_iter().collect())
}
