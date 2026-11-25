use miden_node_db::sqlite::ReadTx;

mod account_vault_updates;
mod select_block_header;
pub(crate) use select_block_header::select_block_header;
mod select_block_header_and_signatures;
mod select_block_headers;
pub(crate) use select_block_headers::select_block_headers;
mod select_existing_note_ids;
mod select_note_inclusion_proofs;
pub(crate) use select_note_inclusion_proofs::select_note_inclusion_proofs;
mod select_protocol_config;
mod select_protocol_config_commitment_at;

/// Typed storage queries within a single read-only database snapshot.
pub struct ReadTransaction<'a> {
    inner: &'a ReadTx<'a>,
}

impl<'a> ReadTransaction<'a> {
    pub(crate) fn new(inner: &'a ReadTx<'a>) -> Self {
        Self { inner }
    }
}
