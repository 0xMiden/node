//! Database query functions for the NTX builder.

use diesel::prelude::*;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;

use crate::actor::account_effect::NetworkAccountEffect;
use crate::db::errors::DatabaseError;
use crate::db::models::conv as conversions;
use crate::db::schema;

mod accounts;
pub use accounts::*;

mod chain_state;
pub use chain_state::*;

mod notes;
pub use notes::*;

#[cfg(test)]
mod tests;

// STARTUP QUERIES
// ================================================================================================

/// Purges all inflight state. Called on startup to get a clean state.
///
/// - Deletes account rows with `transaction_id IS NOT NULL`.
/// - Deletes note rows with `created_by IS NOT NULL`.
/// - Sets `consumed_by = NULL` on notes consumed by inflight transactions.
///
/// # Raw SQL
///
/// ```sql
/// DELETE FROM accounts WHERE transaction_id IS NOT NULL
///
/// DELETE FROM notes WHERE created_by IS NOT NULL
///
/// UPDATE notes SET consumed_by = NULL WHERE consumed_by IS NOT NULL
/// ```
pub fn purge_inflight(conn: &mut SqliteConnection) -> Result<(), DatabaseError> {
    // Delete inflight account rows.
    diesel::delete(schema::accounts::table.filter(schema::accounts::transaction_id.is_not_null()))
        .execute(conn)?;

    // Delete inflight-created notes.
    diesel::delete(schema::notes::table.filter(schema::notes::created_by.is_not_null()))
        .execute(conn)?;

    // Un-nullify notes consumed by inflight transactions.
    diesel::update(schema::notes::table.filter(schema::notes::consumed_by.is_not_null()))
        .set(schema::notes::consumed_by.eq(None::<Vec<u8>>))
        .execute(conn)?;

    Ok(())
}

// MEMPOOL EVENT HANDLERS
// ================================================================================================

/// Handles a `TransactionAdded` event by writing effects to the DB.
///
/// # Raw SQL
///
/// For account updates (applies delta to latest state and inserts inflight row):
///
/// ```sql
/// -- Fetch latest account (see latest_account)
/// INSERT INTO accounts (account_id, transaction_id, account_data)
/// VALUES (?1, ?2, ?3)
/// ```
///
/// Per note (idempotent via `INSERT OR IGNORE`):
///
/// ```sql
/// INSERT OR IGNORE INTO notes
///     (nullifier, account_id, note_data, attempt_count, last_attempt, created_by, consumed_by)
/// VALUES (?1, ?2, ?3, 0, NULL, ?4, NULL)
/// ```
///
/// Per nullifier (marks notes as consumed):
///
/// ```sql
/// UPDATE notes
/// SET consumed_by = ?1
/// WHERE nullifier = ?2 AND consumed_by IS NULL
/// ```
pub fn add_transaction(
    conn: &mut SqliteConnection,
    tx_id: &TransactionId,
    account_delta: Option<&AccountUpdateDetails>,
    notes: &[SingleTargetNetworkNote],
    nullifiers: &[Nullifier],
) -> Result<(), DatabaseError> {
    let tx_id_bytes = conversions::transaction_id_to_bytes(tx_id);

    // Process account delta.
    if let Some(update) = account_delta.and_then(NetworkAccountEffect::from_protocol) {
        let account_id = update.network_account_id();
        match update {
            NetworkAccountEffect::Updated(ref account_delta) => {
                // Query latest_account, apply delta, insert inflight row.
                let current_account =
                    latest_account(conn, account_id)?.expect("account must exist to apply delta");
                let mut updated = current_account;
                updated.apply_delta(account_delta).expect(
                    "network account delta should apply since it was accepted by the mempool",
                );

                let insert = AccountInsert {
                    account_id: conversions::network_account_id_to_bytes(account_id),
                    transaction_id: Some(tx_id_bytes.clone()),
                    account_data: conversions::account_to_bytes(&updated),
                };
                diesel::insert_into(schema::accounts::table).values(&insert).execute(conn)?;
            },
            NetworkAccountEffect::Created(ref account) => {
                let insert = AccountInsert {
                    account_id: conversions::network_account_id_to_bytes(account_id),
                    transaction_id: Some(tx_id_bytes.clone()),
                    account_data: conversions::account_to_bytes(account),
                };
                diesel::insert_into(schema::accounts::table).values(&insert).execute(conn)?;
            },
        }
    }

    // Insert notes with created_by = tx_id.
    // Uses INSERT OR IGNORE to make this idempotent if the same event is delivered twice
    // (the nullifier PK would otherwise cause a constraint violation).
    for note in notes {
        let insert = NoteInsert {
            nullifier: conversions::nullifier_to_bytes(&note.nullifier()),
            account_id: conversions::network_account_id_to_bytes(note.account_id()),
            note_data: conversions::single_target_note_to_bytes(note),
            attempt_count: 0,
            last_attempt: None,
            created_by: Some(tx_id_bytes.clone()),
            consumed_by: None,
        };
        diesel::insert_or_ignore_into(schema::notes::table)
            .values(&insert)
            .execute(conn)?;
    }

    // Mark consumed notes: set consumed_by = tx_id for matching nullifiers.
    for nullifier in nullifiers {
        let nullifier_bytes = conversions::nullifier_to_bytes(nullifier);

        // Only mark notes that are not already consumed.
        diesel::update(
            schema::notes::table
                .find(&nullifier_bytes)
                .filter(schema::notes::consumed_by.is_null()),
        )
        .set(schema::notes::consumed_by.eq(Some(&tx_id_bytes)))
        .execute(conn)?;
    }

    Ok(())
}

/// Handles a `BlockCommitted` event by committing transaction effects.
///
/// # Raw SQL
///
/// Per committed transaction:
///
/// ```sql
/// -- Find inflight accounts for this tx
/// SELECT account_id FROM accounts WHERE transaction_id = ?1
///
/// -- Delete old committed row
/// DELETE FROM accounts WHERE account_id = ?1 AND transaction_id IS NULL
///
/// -- Promote inflight row to committed
/// UPDATE accounts SET transaction_id = NULL
/// WHERE account_id = ?1 AND transaction_id = ?2
///
/// -- Delete consumed notes
/// DELETE FROM notes WHERE consumed_by = ?1
///
/// -- Promote inflight-created notes to committed
/// UPDATE notes SET created_by = NULL WHERE created_by = ?1
/// ```
///
/// Finally updates chain state (see [`upsert_chain_state`]).
pub fn handle_block_committed(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
    block_num: BlockNumber,
    block_header: &BlockHeader,
) -> Result<(), DatabaseError> {
    for tx_id in tx_ids {
        let tx_id_bytes = conversions::transaction_id_to_bytes(tx_id);

        // Promote inflight account rows: delete old committed, set transaction_id = NULL.
        // Find accounts that have an inflight row for this tx.
        let inflight_account_ids: Vec<Vec<u8>> = schema::accounts::table
            .filter(schema::accounts::transaction_id.eq(&tx_id_bytes))
            .select(schema::accounts::account_id)
            .load(conn)?;

        for account_id_bytes in &inflight_account_ids {
            // Delete the old committed row for this account.
            diesel::delete(
                schema::accounts::table
                    .filter(schema::accounts::account_id.eq(account_id_bytes))
                    .filter(schema::accounts::transaction_id.is_null()),
            )
            .execute(conn)?;

            // Promote the inflight row to committed (set transaction_id = NULL).
            // Only promote the row for this specific tx.
            diesel::update(
                schema::accounts::table
                    .filter(schema::accounts::account_id.eq(account_id_bytes))
                    .filter(schema::accounts::transaction_id.eq(&tx_id_bytes)),
            )
            .set(schema::accounts::transaction_id.eq(None::<Vec<u8>>))
            .execute(conn)?;
        }

        // Delete consumed notes (consumed_by = tx_id).
        diesel::delete(schema::notes::table.filter(schema::notes::consumed_by.eq(&tx_id_bytes)))
            .execute(conn)?;

        // Promote inflight-created notes to committed (set created_by = NULL).
        diesel::update(schema::notes::table.filter(schema::notes::created_by.eq(&tx_id_bytes)))
            .set(schema::notes::created_by.eq(None::<Vec<u8>>))
            .execute(conn)?;
    }

    // Update chain state.
    upsert_chain_state(conn, block_num, block_header)?;

    Ok(())
}

/// Handles a `TransactionsReverted` event by undoing transaction effects.
///
/// Returns the list of account IDs whose creation was reverted (no committed row exists for that
/// account after removing the inflight rows).
///
/// # Raw SQL
///
/// Per reverted transaction:
///
/// ```sql
/// -- Find affected accounts
/// SELECT account_id FROM accounts WHERE transaction_id = ?1
///
/// -- Delete inflight account rows
/// DELETE FROM accounts WHERE transaction_id = ?1
///
/// -- Check if account creation was fully reverted
/// SELECT COUNT(*) FROM accounts WHERE account_id = ?1
///
/// -- Delete inflight-created notes
/// DELETE FROM notes WHERE created_by = ?1
///
/// -- Restore consumed notes
/// UPDATE notes SET consumed_by = NULL WHERE consumed_by = ?1
/// ```
pub fn handle_transactions_reverted(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
) -> Result<Vec<NetworkAccountId>, DatabaseError> {
    let mut reverted_accounts = Vec::new();

    for tx_id in tx_ids {
        let tx_id_bytes = conversions::transaction_id_to_bytes(tx_id);

        // Find accounts affected by this transaction.
        let affected_account_ids: Vec<Vec<u8>> = schema::accounts::table
            .filter(schema::accounts::transaction_id.eq(&tx_id_bytes))
            .select(schema::accounts::account_id)
            .load(conn)?;

        // Delete inflight account rows for this tx.
        diesel::delete(
            schema::accounts::table.filter(schema::accounts::transaction_id.eq(&tx_id_bytes)),
        )
        .execute(conn)?;

        // Check if any affected accounts had their creation fully reverted
        // (no committed row and no remaining inflight rows).
        for account_id_bytes in &affected_account_ids {
            let remaining: i64 = schema::accounts::table
                .filter(schema::accounts::account_id.eq(account_id_bytes))
                .count()
                .get_result(conn)?;

            if remaining == 0 {
                let account_id = conversions::network_account_id_from_bytes(account_id_bytes)?;
                reverted_accounts.push(account_id);
            }
        }

        // Delete inflight-created notes (created_by = tx_id).
        diesel::delete(schema::notes::table.filter(schema::notes::created_by.eq(&tx_id_bytes)))
            .execute(conn)?;

        // Un-nullify consumed notes (set consumed_by = NULL where consumed_by = tx_id).
        diesel::update(schema::notes::table.filter(schema::notes::consumed_by.eq(&tx_id_bytes)))
            .set(schema::notes::consumed_by.eq(None::<Vec<u8>>))
            .execute(conn)?;
    }

    Ok(reverted_accounts)
}
