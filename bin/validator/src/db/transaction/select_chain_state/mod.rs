use miden_node_db::DatabaseError;
use miden_protocol::block::BlockHeader;

use super::ReadTransaction;
use crate::db::ChainState;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Reads the confirmed tip and its pending child from the same snapshot.
    pub(crate) fn select_chain_state(&self) -> Result<Option<ChainState>, DatabaseError> {
        let mut headers = self.inner.query(SQL, &[], |row| row.get::<BlockHeader>(0))?;
        let Some(tip) = headers.pop() else {
            return Ok(None);
        };
        Ok(Some(ChainState { tip, pending: headers.pop() }))
    }
}
