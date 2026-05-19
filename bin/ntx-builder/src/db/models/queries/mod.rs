//! Database query functions for the NTX builder.

use std::collections::HashSet;

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::crypto::merkle::mmr::PartialMmr;

use super::account_effect::NetworkAccountEffect;
use crate::committed_block::CommittedBlockEffects;
use crate::db::models::conv as conversions;
use crate::db::schema;

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

// COMMITTED BLOCK HANDLER
// ================================================================================================

/// Applies the network-relevant effects of a committed block to the local DB.
///
/// In a single transaction:
/// - Updates or creates network account state from the block's account updates.
/// - Inserts newly created network notes.
/// - Marks notes consumed by the block's nullifiers as committed at this block.
/// - Updates the chain state singleton to point at this block.
///
/// Returns the set of network account IDs whose state changed and whose active actors (if any)
/// should be notified to re-evaluate their work.
pub fn apply_committed_block(
    conn: &mut SqliteConnection,
    effects: &CommittedBlockEffects,
    chain_mmr: &PartialMmr,
) -> Result<Vec<NetworkAccountId>, DatabaseError> {
    let block_num = effects.header.block_num();
    let mut affected_accounts: HashSet<NetworkAccountId> = HashSet::new();

    // Apply account updates.
    for (network_id, details) in &effects.network_account_updates {
        let Some(effect) = NetworkAccountEffect::from_protocol(details) else {
            continue;
        };
        match effect {
            NetworkAccountEffect::Created(account) => {
                upsert_account(conn, *network_id, &account)?;
            },
            NetworkAccountEffect::Updated(delta) => {
                let mut account = get_account(conn, *network_id)?.ok_or_else(|| {
                    DatabaseError::Io(std::io::Error::other(format!(
                        "account {network_id} must exist to apply committed delta from block \
                         {block_num}"
                    )))
                })?;
                account
                    .apply_delta(&delta)
                    .expect("committed account delta should apply cleanly");
                upsert_account(conn, *network_id, &account)?;
            },
        }
        affected_accounts.insert(*network_id);
    }

    // Insert newly created network notes.
    if !effects.network_notes.is_empty() {
        for note in &effects.network_notes {
            let target_id = NetworkAccountId::try_from(note.target_account_id())
                .expect("network note's target account must be a network account");
            affected_accounts.insert(target_id);
        }
        insert_committed_notes(conn, &effects.network_notes)?;
    }

    // Mark consumed notes as committed.
    let block_num_val = conversions::block_num_to_i64(block_num);
    for nullifier in &effects.nullifiers {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);
        // Collect affected account ids for matching notes before updating.
        let matched_accounts: Vec<Vec<u8>> = schema::notes::table
            .filter(schema::notes::nullifier.eq(&nullifier_bytes))
            .filter(schema::notes::committed_at.is_null())
            .select(schema::notes::account_id)
            .load(conn)?;
        for account_id_bytes in &matched_accounts {
            affected_accounts.insert(conversions::network_account_id_from_bytes(account_id_bytes)?);
        }

        diesel::update(
            schema::notes::table
                .find(&nullifier_bytes)
                .filter(schema::notes::committed_at.is_null()),
        )
        .set(schema::notes::committed_at.eq(Some(block_num_val)))
        .execute(conn)?;
    }

    // Update chain state singleton.
    upsert_chain_state(conn, block_num, &effects.header, chain_mmr)?;

    Ok(affected_accounts.into_iter().collect())
}
