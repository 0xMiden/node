//! Database query functions for the NTX builder.
//!
//! ## Organization
//!
//! Queries are split by domain entity:
//! - [`accounts`] — committed accounts and inflight account deltas.
//! - [`notes`] — committed/inflight notes, nullifiers, and note failure tracking.
//! - [`chain_state`] — singleton chain state (block number + header).
//! - [`transactions`] — inflight transaction models.
//!
//! Cross-cutting functions that span multiple domains (e.g. mempool event handlers) live here in
//! `mod.rs`.
//!
//! ## Naming
//!
//! * Function names use `upsert_`, `insert_`, `select_` or `handle_` prefixes.
//! * `*Insert` types implement `diesel::Insertable`.
//! * `*Row` types implement `diesel::Queryable` and `diesel::Selectable`.
//!
//! ## Assumptions
//!
//! Functions in this module can assume they are called within the scope of a transaction. Nesting
//! further `transaction(conn, || {})` calls has no effect and should be considered unnecessary.

use diesel::prelude::*;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;

use crate::actor::note_state::NetworkAccountEffect;
use crate::db::errors::DatabaseError;
use crate::db::models::conv as conversions;
use crate::db::schema;

mod accounts;
pub use accounts::*;

mod chain_state;
pub use chain_state::*;

mod notes;
pub use notes::*;

mod transactions;
pub use transactions::*;

// STARTUP QUERIES
// ================================================================================================

/// Purges all inflight state. Called on startup to get a clean slate.
pub fn purge_inflight(conn: &mut SqliteConnection) -> Result<(), DatabaseError> {
    diesel::delete(schema::inflight_account_deltas::table).execute(conn)?;
    diesel::delete(schema::inflight_notes::table).execute(conn)?;
    diesel::delete(schema::inflight_nullifiers::table).execute(conn)?;
    diesel::delete(schema::inflight_transactions::table).execute(conn)?;
    diesel::delete(schema::predating_events::table).execute(conn)?;
    Ok(())
}

// MEMPOOL EVENT HANDLERS
// ================================================================================================

/// Handles a `TransactionAdded` event by writing effects to the DB.
/// (Design doc 3.3)
pub fn handle_transaction_added(
    conn: &mut SqliteConnection,
    tx_id: &TransactionId,
    account_delta: Option<&AccountUpdateDetails>,
    notes: &[SingleTargetNetworkNote],
    nullifiers: &[Nullifier],
) -> Result<(), DatabaseError> {
    let tx_id_bytes = conversions::transaction_id_to_bytes(tx_id);

    // Check if we already tracked this transaction (dedup).
    let already_tracked = schema::inflight_transactions::table
        .find(&tx_id_bytes)
        .count()
        .get_result::<i64>(conn)?
        > 0;
    if already_tracked {
        return Ok(());
    }

    // Determine account delta impact.
    let mut delta_account_id_bytes: Option<Vec<u8>> = None;

    if let Some(update) = account_delta.and_then(NetworkAccountEffect::from_protocol) {
        let account_id = update.network_account_id();
        match update {
            NetworkAccountEffect::Updated(ref account_delta) => {
                // Query latest_account, apply delta, insert into inflight_account_deltas.
                let current_account =
                    latest_account(conn, account_id)?.expect("account must exist to apply delta");
                let mut updated = current_account;
                updated.apply_delta(account_delta).expect(
                    "network account delta should apply since it was accepted by the mempool",
                );

                let insert = InflightDeltaInsert {
                    account_id: conversions::network_account_id_to_bytes(account_id),
                    transaction_id: tx_id_bytes.clone(),
                    account_data: conversions::account_to_bytes(&updated),
                };
                diesel::insert_into(schema::inflight_account_deltas::table)
                    .values(&insert)
                    .execute(conn)?;

                delta_account_id_bytes = Some(conversions::network_account_id_to_bytes(account_id));
            },
            NetworkAccountEffect::Created(ref account) => {
                // Account creation goes into inflight_account_deltas.
                let insert = InflightDeltaInsert {
                    account_id: conversions::network_account_id_to_bytes(account_id),
                    transaction_id: tx_id_bytes.clone(),
                    account_data: conversions::account_to_bytes(account),
                };
                diesel::insert_into(schema::inflight_account_deltas::table)
                    .values(&insert)
                    .execute(conn)?;

                delta_account_id_bytes = Some(conversions::network_account_id_to_bytes(account_id));
            },
        }
    }

    // Insert notes into inflight_notes.
    for note in notes {
        let account_id_bytes = conversions::network_account_id_to_bytes(note.account_id());
        let insert = InflightNoteInsert {
            nullifier: conversions::nullifier_to_bytes(&note.nullifier()),
            account_id: account_id_bytes,
            transaction_id: tx_id_bytes.clone(),
            note_data: conversions::single_target_note_to_bytes(note),
            attempt_count: 0,
            last_attempt: None,
        };
        diesel::insert_into(schema::inflight_notes::table)
            .values(&insert)
            .execute(conn)?;
    }

    // Process nullifiers: move consumed notes to inflight_nullifiers.
    insert_inflight_nullifiers(conn, nullifiers, &tx_id_bytes)?;

    // Record the transaction.
    let tx_insert = InflightTransactionInsert {
        transaction_id: tx_id_bytes,
        delta_account_id: delta_account_id_bytes,
    };
    diesel::insert_into(schema::inflight_transactions::table)
        .values(&tx_insert)
        .execute(conn)?;

    Ok(())
}

/// Handles a `BlockCommitted` event by committing transaction effects.
/// (Design doc 3.4)
pub fn handle_block_committed(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
    block_num: BlockNumber,
    block_header: &BlockHeader,
) -> Result<(), DatabaseError> {
    for tx_id in tx_ids {
        let tx_id_bytes = conversions::transaction_id_to_bytes(tx_id);

        // Look up the transaction.
        let tx_row: Option<InflightTransactionRow> = schema::inflight_transactions::table
            .find(&tx_id_bytes)
            .select(InflightTransactionRow::as_select())
            .first(conn)
            .optional()?;

        let Some(tx_row) = tx_row else {
            // Transaction not tracked (no impact on network state).
            continue;
        };

        // Commit account delta: find the delta for this specific transaction.
        if let Some(ref delta_account_id) = tx_row.delta_account_id {
            let delta: Option<InflightDeltaRow> = schema::inflight_account_deltas::table
                .filter(schema::inflight_account_deltas::account_id.eq(delta_account_id))
                .filter(schema::inflight_account_deltas::transaction_id.eq(&tx_id_bytes))
                .select(InflightDeltaRow::as_select())
                .first(conn)
                .optional()?;

            if let Some(delta) = delta {
                // Upsert committed_accounts.
                let committed = CommittedAccountInsert {
                    account_id: delta.account_id,
                    account_data: delta.account_data,
                };
                diesel::replace_into(schema::committed_accounts::table)
                    .values(&committed)
                    .execute(conn)?;

                // Delete the committed delta.
                diesel::delete(
                    schema::inflight_account_deltas::table
                        .filter(schema::inflight_account_deltas::id.eq(delta.id)),
                )
                .execute(conn)?;
            }
        }

        // Move inflight_notes created by this tx -> committed_notes.
        let inflight_notes: Vec<InflightNoteRow> = schema::inflight_notes::table
            .filter(schema::inflight_notes::transaction_id.eq(&tx_id_bytes))
            .select(InflightNoteRow::as_select())
            .load(conn)?;
        for note_row in &inflight_notes {
            let committed = CommittedNoteInsert {
                nullifier: note_row.nullifier.clone(),
                account_id: note_row.account_id.clone(),
                note_data: note_row.note_data.clone(),
                attempt_count: note_row.attempt_count,
                last_attempt: note_row.last_attempt,
            };
            diesel::replace_into(schema::committed_notes::table)
                .values(&committed)
                .execute(conn)?;
        }
        diesel::delete(
            schema::inflight_notes::table
                .filter(schema::inflight_notes::transaction_id.eq(&tx_id_bytes)),
        )
        .execute(conn)?;

        // Delete inflight_nullifiers for this tx (consumed notes are fully committed).
        let committed_nullifiers: Vec<Vec<u8>> = schema::inflight_nullifiers::table
            .filter(schema::inflight_nullifiers::transaction_id.eq(&tx_id_bytes))
            .select(schema::inflight_nullifiers::nullifier)
            .load(conn)?;
        for nullifier_bytes in &committed_nullifiers {
            // Delete the consumed note from both committed_notes and inflight_notes.
            diesel::delete(
                schema::committed_notes::table
                    .filter(schema::committed_notes::nullifier.eq(nullifier_bytes)),
            )
            .execute(conn)?;
            diesel::delete(
                schema::inflight_notes::table
                    .filter(schema::inflight_notes::nullifier.eq(nullifier_bytes)),
            )
            .execute(conn)?;
        }
        diesel::delete(
            schema::inflight_nullifiers::table
                .filter(schema::inflight_nullifiers::transaction_id.eq(&tx_id_bytes)),
        )
        .execute(conn)?;

        // Delete the transaction record.
        diesel::delete(schema::inflight_transactions::table.find(&tx_id_bytes)).execute(conn)?;
    }

    // Update chain state.
    upsert_chain_state(conn, block_num, block_header)?;

    Ok(())
}

/// Handles a `TransactionsReverted` event by undoing transaction effects.
/// (Design doc 3.5)
///
/// Returns the list of account IDs whose creation was reverted (no committed + no inflight
/// remaining).
pub fn handle_transactions_reverted(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
) -> Result<Vec<NetworkAccountId>, DatabaseError> {
    let mut reverted_accounts = Vec::new();

    for tx_id in tx_ids {
        let tx_id_bytes = conversions::transaction_id_to_bytes(tx_id);

        // Look up the transaction.
        let tx_row: Option<InflightTransactionRow> = schema::inflight_transactions::table
            .find(&tx_id_bytes)
            .select(InflightTransactionRow::as_select())
            .first(conn)
            .optional()?;

        let Some(tx_row) = tx_row else {
            continue;
        };

        // Revert account delta: delete the delta for this specific transaction.
        if let Some(ref delta_account_id) = tx_row.delta_account_id {
            diesel::delete(
                schema::inflight_account_deltas::table
                    .filter(schema::inflight_account_deltas::account_id.eq(delta_account_id))
                    .filter(schema::inflight_account_deltas::transaction_id.eq(&tx_id_bytes)),
            )
            .execute(conn)?;

            // Check if account creation was reverted (no committed + no inflight remaining).
            let has_committed: bool = schema::committed_accounts::table
                .find(delta_account_id)
                .count()
                .get_result::<i64>(conn)?
                > 0;
            let has_inflight: bool = schema::inflight_account_deltas::table
                .filter(schema::inflight_account_deltas::account_id.eq(delta_account_id))
                .count()
                .get_result::<i64>(conn)?
                > 0;

            if !has_committed && !has_inflight {
                let account_id = conversions::network_account_id_from_bytes(delta_account_id)?;
                reverted_accounts.push(account_id);
            }
        }

        // Revert inflight notes: delete notes created by this tx.
        diesel::delete(
            schema::inflight_notes::table
                .filter(schema::inflight_notes::transaction_id.eq(&tx_id_bytes)),
        )
        .execute(conn)?;

        // Revert nullifiers: restore consumed notes back to available.
        // (Inflight nullifiers that point to committed_notes remain in committed_notes;
        //  inflight nullifiers that point to inflight_notes are already deleted above.)
        diesel::delete(
            schema::inflight_nullifiers::table
                .filter(schema::inflight_nullifiers::transaction_id.eq(&tx_id_bytes)),
        )
        .execute(conn)?;

        // Delete the transaction record.
        diesel::delete(schema::inflight_transactions::table.find(&tx_id_bytes)).execute(conn)?;
    }

    Ok(reverted_accounts)
}
