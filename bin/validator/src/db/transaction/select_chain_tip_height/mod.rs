use miden_node_db::DatabaseError;

use super::ReadTransaction;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the height of the latest signed block.
    pub(crate) fn select_chain_tip_height(&self) -> Result<Option<u32>, DatabaseError> {
        Ok(self.inner.query(SQL, &[], |row| row.get(0))?.pop())
    }
}
