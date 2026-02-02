//! Abstracts all relevant queries to individual blocking function calls
//!
//! ## Naming
//!
//! * `fn *` function names have on of three prefixes: `upsert_`, `insert_` or `select_` denoting
//!   their nature. If neither fits, then use your best judgment for naming.
//! * `*Insert` types are used for _inserting_ data into table and _must_ implement
//!   `diesel::Insertable`.
//! * `*RawRow` types are used for _querying_ a _single_ table an _without_ an explicit row and must
//!   implement a `QueryableByName` and `Selectable`.
//! * `*RawJoined` types are used for _querying_ a _left join_ table _without_ an explicit row and
//!   must implement a `QueryableByName` and _cannot_ implement `Selectable`.
//!
//! ## Type conversion
//!
//! The database `*Raw` and `*Joined` types use database primitives. In order to convert to correct
//! in-memory representations it's preferable to have new-types which implement [`SqlTypeConvert`].
//! If that is inconvenient, provide two wrapper methods for the conversion each way. There must be
//! relevant constraints in the table. For convenience, any types that have more complex
//! serialization may use [`Serializable`] and [`Deserializable`] for convenience.
//!
//! ## Assumptions
//!
//! Any call that sits insides of `queries/**/*.rs` can assume it's called within the scope of a
//! transaction, any nesting of further `transaction(conn, || {})` has no effect and should be
//! considered unnecessary boilerplate by default.

#![allow(
    clippy::needless_pass_by_value,
    reason = "The parent scope does own it, passing by value avoids additional boilerplate"
)]

use diesel::SqliteConnection;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockAccountUpdate, BlockHeader, BlockNumber};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::OrderedTransactionHeaders;

use super::DatabaseError;
use crate::db::{NoteRecord, StateSyncUpdate};
use crate::errors::StateSyncError;

mod transactions;
pub use transactions::*;
mod block_headers;
pub use block_headers::*;
mod accounts;
pub use accounts::*;
mod nullifiers;
pub(crate) use nullifiers::*;
mod notes;
pub(crate) use notes::*;

/// Apply a new block to the state
///
/// # Returns
///
/// Number of records inserted and/or updated.
pub(crate) fn apply_block(
    conn: &mut SqliteConnection,
    block_header: &BlockHeader,
    signature: &Signature,
    notes: &[(NoteRecord, Option<Nullifier>)],
    nullifiers: &[Nullifier],
    accounts: &[BlockAccountUpdate],
    transactions: &OrderedTransactionHeaders,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    // Note: ordering here is important as the relevant tables have FK dependencies.
    count += insert_block_header(conn, block_header, signature)?;
    count += upsert_accounts(conn, accounts, block_header.block_num())?;
    count += insert_scripts(conn, notes.iter().map(|(note, _)| note))?;
    count += insert_notes(conn, notes)?;
    count += insert_transactions(conn, block_header.block_num(), transactions)?;
    count += insert_nullifiers_for_block(conn, nullifiers, block_header.block_num())?;
    Ok(count)
}

/// Loads the state necessary for a state sync
///
/// The state sync covers from `from_start_block` until the last block that has a note matching the
/// given `note_tags`.
pub(crate) fn get_state_sync(
    conn: &mut SqliteConnection,
    from_start_block: BlockNumber,
    account_ids: Vec<AccountId>,
    note_tags: Vec<u32>,
) -> Result<StateSyncUpdate, StateSyncError> {
    let chain_tip = select_block_header_by_block_num(conn, None)?
        .expect("Chain tip is not found")
        .block_num();

    // Sync notes from the starting block to the latest in the chain.
    let block_range = from_start_block..=chain_tip;

    // select notes since block by tag and sender
    let (notes, _) = select_notes_since_block_by_tag_and_sender(
        conn,
        &account_ids[..],
        &note_tags[..],
        block_range,
    )?;

    // select block header by block num
    let maybe_note_block_num = notes.first().map(|note| note.block_num);
    let block_header: BlockHeader = select_block_header_by_block_num(conn, maybe_note_block_num)?
        .ok_or_else(|| StateSyncError::EmptyBlockHeadersTable)?;

    // select accounts by block range
    let to_end_block = block_header.block_num();
    let account_updates =
        select_accounts_by_block_range(conn, &account_ids, from_start_block..=to_end_block)?;

    // select transactions by accounts and block range
    let transactions = select_transactions_by_accounts_and_block_range(
        conn,
        &account_ids,
        from_start_block..=to_end_block,
    )?;
    Ok(StateSyncUpdate {
        notes,
        block_header,
        account_updates,
        transactions,
    })
}
