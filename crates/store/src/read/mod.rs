//! Consistent store reads composed by the caller.

pub(crate) mod acquire;
mod snapshot;
mod validate_storage_map_slots;
pub use validate_storage_map_slots::validate_storage_map_slots;
mod transaction;

pub use snapshot::StateSnapshot;
pub use transaction::ReadTransaction;
pub(crate) use transaction::{
    select_block_header,
    select_block_headers,
    select_note_inclusion_proofs,
};

/// A read-only database transaction and tree snapshot at the same committed block.
///
/// The store lends this view to a synchronous closure on a blocking worker. All database reads
/// share one SQLite transaction, and neither the transaction nor the snapshot can escape the closure.
pub struct ReadView<'a> {
    pub tx: ReadTransaction<'a>,
    pub snapshot: &'a StateSnapshot<'a>,
}

#[cfg(test)]
pub(crate) mod tests;
