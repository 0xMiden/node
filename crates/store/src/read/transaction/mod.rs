use miden_node_db::sqlite::ReadTx;

mod filter_network_accounts;
mod select_account_storage_map_values_paged;
pub use select_account_storage_map_values_paged::StorageMapValue;
mod select_account_vault_assets;
mod select_block_header;
pub(crate) use select_block_header::select_block_header;
mod select_block_header_and_signatures;
mod select_block_headers;
pub(crate) use select_block_headers::select_block_headers;
mod select_existing_note_ids;
mod select_note_inclusion_proofs;
pub(crate) use select_note_inclusion_proofs::select_note_inclusion_proofs;
mod select_note_script_by_root;
mod select_note_sync_updates;
#[cfg(test)]
pub(crate) use select_note_sync_updates::{NOTE_SYNC_BLOCK_OVERHEAD_BYTES, NOTE_SYNC_RECORD_BYTES};
mod select_notes_by_id;
mod select_nullifiers_by_prefix;
mod select_protocol_config;
mod select_protocol_config_commitment_at;
mod select_transaction_logs;
mod select_transactions_records;

/// Typed storage queries within a single read-only database snapshot.
pub struct ReadTransaction<'a> {
    inner: &'a ReadTx<'a>,
}

impl<'a> ReadTransaction<'a> {
    pub(crate) fn new(inner: &'a ReadTx<'a>) -> Self {
        Self { inner }
    }
}
