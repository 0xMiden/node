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

use diesel::SqliteConnection;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::block::{BlockAccountUpdate, BlockHeader};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::OrderedTransactionHeaders;

use super::DatabaseError;
use crate::db::NoteRecord;

mod transactions;
pub use transactions::*;
mod block_headers;
pub use block_headers::*;
mod accounts;
pub use accounts::*;
mod nullifiers;
pub use nullifiers::NullifiersPage;
pub(crate) use nullifiers::*;
mod notes;
pub(crate) use notes::*;

/// All data needed to apply a new block to the database.
pub(crate) struct ApplyBlockData<'a> {
    pub block_header: &'a BlockHeader,
    pub signature: &'a Signature,
    pub notes: &'a [(NoteRecord, Option<Nullifier>)],
    pub nullifiers: &'a [Nullifier],
    pub accounts: &'a [BlockAccountUpdate],
    pub transactions: &'a OrderedTransactionHeaders,
    pub proving_inputs: Option<Vec<u8>>,
}

/// Apply a new block to the state
///
/// # Returns
///
/// Number of records inserted and/or updated.
pub(crate) fn apply_block(
    conn: &mut SqliteConnection,
    data: ApplyBlockData<'_>,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    // Note: ordering here is important as the relevant tables have FK dependencies.
    count += insert_block_header(conn, data.block_header, data.signature, data.proving_inputs)?;
    count += upsert_accounts(conn, data.accounts, data.block_header.block_num())?;
    count += insert_scripts(conn, data.notes.iter().map(|(note, _)| note))?;
    count += insert_notes(conn, data.notes)?;
    count += insert_transactions(conn, data.block_header.block_num(), data.transactions)?;
    count += insert_nullifiers_for_block(conn, data.nullifiers, data.block_header.block_num())?;
    Ok(count)
}
