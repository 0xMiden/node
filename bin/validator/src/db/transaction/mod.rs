//! Read and write transactions for the validator database.

use std::num::NonZeroU32;
use std::ops::Deref;

use miden_node_db::sqlite::{ReadTx, WriteTx};

mod pending_validator_quorum;
mod select_chain_state;
mod select_chain_tip;
mod select_chain_tip_height;
mod upsert_signed_block;

/// Read queries against one database snapshot.
pub(crate) struct ReadTransaction<'tx> {
    inner: &'tx ReadTx<'tx>,
}

impl<'tx> ReadTransaction<'tx> {
    pub(super) fn new(inner: &'tx ReadTx<'tx>) -> Self {
        Self { inner }
    }
}

/// Read and write queries on the same SQLite writer connection.
pub(crate) struct WriteTransaction<'tx> {
    inner: &'tx WriteTx<'tx>,
    read: ReadTransaction<'tx>,
    proving_input_retention_blocks: NonZeroU32,
}

impl<'tx> WriteTransaction<'tx> {
    pub(super) fn new(
        inner: &'tx WriteTx<'tx>,
        proving_input_retention_blocks: NonZeroU32,
    ) -> Self {
        Self {
            inner,
            read: ReadTransaction::new(inner),
            proving_input_retention_blocks,
        }
    }
}

impl<'tx> Deref for WriteTransaction<'tx> {
    type Target = ReadTransaction<'tx>;

    fn deref(&self) -> &Self::Target {
        &self.read
    }
}
