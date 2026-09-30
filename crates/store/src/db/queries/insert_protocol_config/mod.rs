//! Inserts a protocol configuration at its activation block.

use miden_node_db::sqlite::WriteTx;
use miden_node_tracing::miden_instrument;
use miden_protocol::block::BlockNumber;
use miden_protocol::protocol_config::ProtocolConfig;

use crate::COMPONENT;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("insert_protocol_config.sql");

/// Inserts a [`ProtocolConfig`] that becomes active at `block_number`.
///
/// The row also stores the configuration commitment. Readers use it to find the configuration by
/// commitment.
///
/// # Returns
///
/// The number of affected rows.
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub(crate) fn insert_protocol_config(
    tx: &WriteTx<'_>,
    protocol_config: &ProtocolConfig,
    block_number: BlockNumber,
) -> Result<usize, DatabaseError> {
    let commitment = protocol_config.to_commitment();

    Ok(tx.execute(SQL, &[&commitment, &block_number, protocol_config])?)
}
