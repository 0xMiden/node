//! Writes every table a committed block touches.

use miden_node_db::sqlite::WriteTx;
use miden_protocol::block::SignedBlock;
use miden_protocol::note::Nullifier;

use crate::db::NoteRecord;
use crate::db::queries::{
    PrecomputedPublicAccountStates,
    insert_block_header,
    insert_note_scripts,
    insert_notes,
    insert_nullifiers_for_block,
    insert_transactions,
    upsert_accounts,
};
use crate::errors::DatabaseError;

/// Apply a new block to the state.
///
/// # Returns
///
/// Number of records inserted and/or updated.
pub(crate) fn apply_block(
    tx: &WriteTx<'_>,
    block: &SignedBlock,
    notes: &[(NoteRecord, Option<Nullifier>)],
    precomputed_public_states: &PrecomputedPublicAccountStates,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    // Note: ordering here is important as the relevant tables have FK dependencies.
    count += insert_block_header(tx, block.header(), block.signatures())?;
    count += upsert_accounts(
        tx,
        block.body().updated_accounts(),
        block.header().block_num(),
        precomputed_public_states,
    )?;
    count += insert_note_scripts(tx, notes.iter().map(|(note, _)| note))?;
    count += insert_notes(tx, notes)?;
    count += insert_transactions(tx, block.header().block_num(), block.body().transactions())?;
    count += insert_nullifiers_for_block(
        tx,
        block.body().created_nullifiers(),
        block.header().block_num(),
    )?;
    Ok(count)
}
