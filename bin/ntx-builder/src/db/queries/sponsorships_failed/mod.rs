//! Records the latest failure of a set of `FEE_SPONSORSHIP` notes.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_node_tracing::ErrorReport;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::NoteError;

const SQL: &str = include_str!("sponsorship_failed.sql");

/// Marks `FEE_SPONSORSHIP` notes as failed by setting `last_attempt` and storing the latest error
/// message. Nullifiers that are not in `sponsorship_notes` match no row.
pub fn sponsorships_failed(
    tx: &WriteTx<'_>,
    failed_sponsorships: &[(Nullifier, NoteError)],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = block_num.to_raw_sql();

    for (nullifier, error) in failed_sponsorships {
        let error_report = error.as_report();
        tx.execute(SQL, &[nullifier, &block_num_val, &error_report])?;
    }
    Ok(())
}
