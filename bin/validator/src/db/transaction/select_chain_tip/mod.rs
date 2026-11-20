use miden_node_db::DatabaseError;
use miden_protocol::block::BlockHeader;

use super::ReadTransaction;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the latest signed header, or `None` before bootstrap.
    pub(crate) fn select_chain_tip(&self) -> Result<Option<BlockHeader>, DatabaseError> {
        Ok(self.inner.query(SQL, &[], |row| row.get(0))?.pop())
    }
}
