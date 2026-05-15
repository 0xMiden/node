//! Database query functions for the NTX builder.

use std::collections::HashSet;

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;

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

// LEGACY CLEANUP
// ================================================================================================

/// Removes any leftover "inflight" rows from a previous run of the ntx-builder under the old
/// mempool-subscription model.
///
/// The new committed-block model never writes inflight state (`transaction_id`, `created_by`,
/// `consumed_by`), but those columns still exist on the schema and pre-existing rows from an
/// in-place upgrade would otherwise be returned by `get_account` and skew availability queries.
/// Idempotent and cheap on a clean DB.
///
/// # Raw SQL
///
/// ```sql
/// DELETE FROM accounts WHERE transaction_id IS NOT NULL
///
/// DELETE FROM notes WHERE created_by IS NOT NULL AND committed_at IS NULL
///
/// UPDATE notes SET consumed_by = NULL
/// WHERE consumed_by IS NOT NULL AND committed_at IS NULL
/// ```
pub fn purge_legacy_inflight(conn: &mut SqliteConnection) -> Result<(), DatabaseError> {
    diesel::delete(schema::accounts::table.filter(schema::accounts::transaction_id.is_not_null()))
        .execute(conn)?;

    diesel::delete(
        schema::notes::table
            .filter(schema::notes::created_by.is_not_null())
            .filter(schema::notes::committed_at.is_null()),
    )
    .execute(conn)?;

    diesel::update(
        schema::notes::table
            .filter(schema::notes::consumed_by.is_not_null())
            .filter(schema::notes::committed_at.is_null()),
    )
    .set(schema::notes::consumed_by.eq(None::<Vec<u8>>))
    .execute(conn)?;

    Ok(())
}

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
                upsert_committed_account(conn, *network_id, &account)?;
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
                upsert_committed_account(conn, *network_id, &account)?;
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
    upsert_chain_state(conn, block_num, &effects.header)?;

    Ok(affected_accounts.into_iter().collect())
}
