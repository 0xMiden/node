//! Database query functions for the NTX builder.

use std::collections::HashMap;

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::transaction::TransactionId;

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
/// - Updates the singleton `chain_state` row's tip with the new block header and the
///   post-application chain MMR.
///
/// The account upserts apply each block's network-account effects to the local store so the actor's
/// `account_last_tx` landing check and post-expiry reload see the authoritative committed state.
pub fn apply_committed_block(
    conn: &mut SqliteConnection,
    effects: &CommittedBlockEffects,
    chain_mmr: &PartialMmr,
) -> Result<(), DatabaseError> {
    // The latest transaction in this block per account. For block-producer output every committed
    // account update originates from a transaction in the same block, so each upserted account has
    // an entry here. Collecting into a map keeps the last transaction per account (block order is
    // preserved). The genesis block is the sole exception: it commits account state directly with
    // no transactions, so genesis accounts fall back to the zero sentinel below.
    let last_tx: HashMap<AccountId, _> = effects.account_transactions.iter().copied().collect();
    let is_genesis = effects.header.block_num() == BlockNumber::GENESIS;

    for (account_id, details) in &effects.network_account_updates {
        let Some(effect) = NetworkAccountEffect::from_protocol(details) else {
            continue;
        };
        // Genesis seeds account state with no originating transaction, so it stores a zero
        // `TransactionId` sentinel.
        let last_tx_id = last_tx.get(account_id).copied().unwrap_or_else(|| {
            assert!(
                is_genesis,
                "a committed account update must originate from a transaction in the block",
            );
            TransactionId::from_raw(Word::empty())
        });
        match effect {
            NetworkAccountEffect::Created(account) => {
                upsert_account(conn, *account_id, &account, last_tx_id)?;
            },
            NetworkAccountEffect::Updated(patch) => {
                // If the account is not already tracked locally, skip it.
                let Some(mut current) = get_account(conn, *account_id)? else {
                    continue;
                };
                current
                    .apply_patch(&patch)
                    .expect("network account patch should apply since the block was committed");
                upsert_account(conn, *account_id, &current, last_tx_id)?;
            },
        }
    }

    insert_network_notes(conn, &effects.network_notes)?;

    mark_notes_consumed(conn, &effects.nullifiers, effects.header.block_num())?;

    update_chain_state_tip(conn, effects.header.block_num(), &effects.header, chain_mmr)?;

    Ok(())
}
