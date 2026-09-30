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
//! relevant constraints in the table. Structured payloads use the protobuf codecs in
//! `miden_node_persistence`. Keys and indexed values use fixed-width encodings.
//!
//! ## Assumptions
//!
//! Any call that sits insides of `queries/**/*.rs` can assume it's called within the scope of a
//! transaction, any nesting of further `transaction(conn, || {})` has no effect and should be
//! considered unnecessary boilerplate by default.

use super::DatabaseError;

mod transactions;
pub use transactions::*;
mod block_headers;
pub(crate) use block_headers::*;
mod notes;
pub(crate) use notes::*;
