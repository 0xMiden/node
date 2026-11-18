//! Consistent store reads composed by the caller.

mod account;
pub(crate) mod acquire;
mod snapshot;
mod transaction;

pub(crate) use account::open_account_witness;
pub use snapshot::StateSnapshot;
pub use transaction::ReadTransaction;
pub(crate) use transaction::select_block_header;

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
