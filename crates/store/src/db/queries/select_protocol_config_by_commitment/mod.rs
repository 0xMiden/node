//! Compatibility adapter for callers using the pooled database API.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::protocol_config::ProtocolConfig;

use crate::errors::DatabaseError;
use crate::read::ReadTransaction;

pub(crate) fn select_protocol_config_by_commitment(
    tx: &ReadTx<'_>,
    commitment: Word,
) -> Result<Option<ProtocolConfig>, DatabaseError> {
    ReadTransaction::new(tx).select_protocol_config(commitment)
}
