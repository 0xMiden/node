//! Makes the feature notes that just gained a sponsorship eligible again.

use miden_node_db::sqlite::{InList, WriteTx};
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;

use crate::sponsorship::SponsorshipNote;

const SQL: &str = include_str!("reset_sponsored_notes.sql");

/// Clears the backoff of every pending feature note the given sponsorships are bound to, so it is
/// eligible at `block_num`. Returns the number of notes made eligible.
pub fn reset_sponsored_notes(
    tx: &WriteTx<'_>,
    sponsorships: &[SponsorshipNote],
    block_num: BlockNumber,
) -> Result<usize, DatabaseError> {
    if sponsorships.is_empty() {
        return Ok(0);
    }
    let feature_note_ids =
        InList::from_values(sponsorships.iter().map(SponsorshipNote::feature_note_id));

    tx.execute(SQL, &[&feature_note_ids, &block_num.to_raw_sql()])
}
