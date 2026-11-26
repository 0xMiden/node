//! Consistent store reads composed by the caller.

pub(crate) mod acquire;
mod snapshot;
mod transaction;

pub use snapshot::StateSnapshot;
#[cfg(test)]
pub(crate) use transaction::{NOTE_SYNC_BLOCK_OVERHEAD_BYTES, NOTE_SYNC_RECORD_BYTES};
pub use transaction::{ReadTransaction, StorageMapValue};
pub(crate) use transaction::{
    select_block_header,
    select_block_headers,
    select_note_inclusion_proofs,
};

pub use crate::db::pagination::Page;

/// A read-only database transaction and tree snapshot at the same committed block.
///
/// The store lends this view to a synchronous closure on a blocking worker. All database reads
/// share one SQLite transaction, and neither the transaction nor the snapshot can escape the closure.
pub struct ReadView<'a> {
    pub tx: ReadTransaction<'a>,
    pub snapshot: StateSnapshot<'a>,
}

#[cfg(test)]
pub(crate) mod tests;
