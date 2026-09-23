//! Database query functions for the NTX builder.
//!
//! Each function takes a [`ReadTx`](miden_node_db::sqlite::ReadTx) or
//! [`WriteTx`](miden_node_db::sqlite::WriteTx) and is driven from a call site through
//! [`Database::read`](miden_node_db::sqlite::Database::read) /
//! [`Database::write`](miden_node_db::sqlite::Database::write).

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::transaction::TransactionId;

use crate::committed_block::CommittedBlockEffects;
use crate::db::queries::account_effect::NetworkAccountEffect;

pub(crate) mod account_effect;

mod account_exists;
pub use account_exists::account_exists;

mod account_has_pending_notes;
pub use account_has_pending_notes::account_has_pending_notes;

// The committed-transaction landing check reads `last_committed_tx` from the `AccountView` the
// coordinator pushes, so this read accessor is only used by tests to verify that `upsert_account`
// persists `accounts.last_tx_id` correctly.
#[cfg(test)]
mod account_last_tx;
#[cfg(test)]
pub use account_last_tx::account_last_tx;

mod accounts_with_pending_notes;
pub use accounts_with_pending_notes::accounts_with_pending_notes;

mod available_notes;
pub use available_notes::{AvailableNotes, available_notes};

mod discard_notes;
pub use discard_notes::discard_notes;

mod get_account;
pub use get_account::get_account;

mod get_note_status;
pub use get_note_status::{NoteStatusRow, get_note_status};

mod insert_genesis_chain_state;
pub use insert_genesis_chain_state::insert_genesis_chain_state;

mod insert_network_notes;
pub use insert_network_notes::insert_network_notes;

mod insert_note_scripts;
pub use insert_note_scripts::insert_note_script;

mod insert_sponsorship_notes;
pub use insert_sponsorship_notes::insert_sponsorship_notes;

mod lookup_note_script;
pub use lookup_note_script::lookup_note_script;

mod mark_notes_consumed;
pub use mark_notes_consumed::mark_notes_consumed;

mod mark_sponsorships_consumed;
pub use mark_sponsorships_consumed::mark_sponsorships_consumed;

mod notes_failed;
pub use notes_failed::notes_failed;

mod select_chain_state;
pub use select_chain_state::select_chain_state;

mod select_genesis_commitment;
pub use select_genesis_commitment::select_genesis_commitment;

mod select_genesis_validator_keys;
pub use select_genesis_validator_keys::select_genesis_validator_keys;

mod sponsored_accounts;
pub use sponsored_accounts::get_target_account_ids_for_sponsor_notes;

mod sponsorships_for_pending_notes;
pub use sponsorships_for_pending_notes::select_sponsorships_for_pending_notes;

mod update_chain_state_tip;
pub use update_chain_state_tip::update_chain_state_tip;

mod upsert_account;
pub use upsert_account::upsert_account;

#[cfg(test)]
mod tests;

// COMMITTED BLOCK APPLICATION
// ================================================================================================

/// Applies a committed block's effects to the database in a single transaction:
///
/// - Upserts each touched network account: new full-state path insert, partial patches apply to
///   the existing committed row.
/// - Inserts each network note and `FEE_SPONSORSHIP` note (`INSERT OR IGNORE` to tolerate
///   redeliveries).
/// - Marks any of our pending notes (feature and sponsorship alike) whose nullifiers appear in
///   this block as `committed_at = block_num`, preserving the row so the `GetNetworkNoteStatus`
///   endpoint can report the full lifecycle.
/// - Updates the singleton `chain_state` row's tip with the new block header and the
///   post-application chain MMR.
///
/// Returns the accounts whose pending feature notes gained a sponsorship in this block (one entry
/// per sponsorship), so the coordinator can wake their actors: a feature note skipped for lacking a
/// sponsorship becomes viable when its sponsorship arrives later.
///
/// The account upserts apply each block's network-account effects to the local store so an actor's
/// post-expiry reload sees the authoritative committed state. The recorded `accounts.last_tx_id` and
/// the `last_committed_tx` the coordinator pushes to actors both derive from the block's
/// `account_transactions`, so they agree on which transaction last touched each account.
pub fn apply_committed_block(
    tx: &WriteTx<'_>,
    effects: &CommittedBlockEffects,
    chain_mmr: &PartialMmr,
) -> Result<Vec<AccountId>, DatabaseError> {
    // Derive each account's latest transaction from the effects that the coordinator uses. The
    // stored `accounts.last_tx_id` and `AccountView::last_committed_tx` values must agree. Each
    // non-genesis account update has an originating transaction in the same block. Genesis account
    // updates use the zero sentinel because genesis contains no transactions.
    //
    // Landing detection reads `AccountView::last_committed_tx`. The database column records the
    // same committed state.
    let last_tx = effects.latest_tx_per_account();
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
                upsert_account(tx, *account_id, &account, last_tx_id)?;
            },
            NetworkAccountEffect::Updated(patch) => {
                // If the account is not already tracked locally, skip it.
                let Some(mut current) = get_account(tx, *account_id)? else {
                    continue;
                };
                current
                    .apply_patch(&patch)
                    .expect("network account patch should apply since the block was committed");
                upsert_account(tx, *account_id, &current, last_tx_id)?;
            },
        }
    }

    insert_network_notes(tx, &effects.network_notes)?;
    insert_sponsorship_notes(tx, &effects.sponsorship_notes)?;

    mark_notes_consumed(tx, &effects.nullifiers, effects.header.block_num())?;
    mark_sponsorships_consumed(tx, &effects.nullifiers, effects.header.block_num())?;

    // Resolved after the consumption marks so a feature note consumed in this same block does not
    // produce a wakeup.
    let sponsored = get_target_account_ids_for_sponsor_notes(tx, &effects.sponsorship_notes)?;

    update_chain_state_tip(tx, effects.header.block_num(), &effects.header, chain_mmr)?;

    Ok(sponsored)
}
