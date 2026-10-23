use std::time::SystemTime;

use miden_node_db::sqlite::WriteTx;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteId;
use miden_protocol::transaction::TransactionId;

use super::timestamp_micros;

/// Records a request's committed transaction and the service's local confirmation time.
pub fn update_request_delivery(
    tx: &WriteTx<'_>,
    note_id: NoteId,
    transaction_id: TransactionId,
    committed_in_block: BlockNumber,
    confirmed_at: SystemTime,
) -> anyhow::Result<()> {
    tx.execute(
        include_str!("update_request_delivery.sql"),
        &[&transaction_id, &committed_in_block, &timestamp_micros(confirmed_at)?, &note_id],
    )?;
    Ok(())
}
