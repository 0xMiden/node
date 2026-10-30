use miden_node_db::sqlite::ReadTx;

mod select_block_header;
pub(crate) use select_block_header::select_block_header;
mod select_protocol_config;

/// Typed storage queries within a single read-only database snapshot.
pub struct ReadTransaction<'a> {
    inner: &'a ReadTx<'a>,
}

impl<'a> ReadTransaction<'a> {
    pub(crate) fn new(inner: &'a ReadTx<'a>) -> Self {
        Self { inner }
    }
}
