//! Stores protocol configuration activations and loads configurations by commitment.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{ReadTx, WriteTx};
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::protocol_config::ProtocolConfig;

const INSERT_SQL: &str = include_str!("insert.sql");
const SELECT_SQL: &str = include_str!("select.sql");
const SELECT_BEFORE_SQL: &str = include_str!("select_before.sql");

/// Loads a protocol configuration given its commitment.
pub fn load(tx: &ReadTx<'_>, commitment: Word) -> Result<Option<ProtocolConfig>, DatabaseError> {
    Ok(tx
        .query(SELECT_SQL, &[&commitment], |row| row.get::<ProtocolConfig>(0))?
        .into_iter()
        .next())
}

/// Stores an activation and replaces any activation at the same height.
pub fn insert(
    tx: &WriteTx<'_>,
    config: &ProtocolConfig,
    block_number: BlockNumber,
) -> Result<(), DatabaseError> {
    let commitment = config.to_commitment();
    tx.execute(INSERT_SQL, &[&commitment, &block_number, &config])?;
    Ok(())
}

/// Loads the commitment of the latest activation strictly before the given height.
pub fn load_before(
    tx: &ReadTx<'_>,
    block_number: BlockNumber,
) -> Result<Option<Word>, DatabaseError> {
    Ok(tx
        .query(SELECT_BEFORE_SQL, &[&block_number], |row| row.get(0))?
        .into_iter()
        .next())
}
