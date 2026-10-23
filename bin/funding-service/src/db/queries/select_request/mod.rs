use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::note::NoteId;

use super::read_request;
use crate::db::{DatabaseIdentity, StoredRequest};

/// Reads a retained funding request by its note ID, including its delivery record.
pub fn select_request(
    tx: &ReadTx<'_>,
    note_id: NoteId,
    identity: DatabaseIdentity,
) -> Result<Option<StoredRequest>, DatabaseError> {
    Ok(tx
        .query(include_str!("select_request.sql"), &[&note_id], |row| {
            read_request(row, identity)
        })?
        .into_iter()
        .next())
}
