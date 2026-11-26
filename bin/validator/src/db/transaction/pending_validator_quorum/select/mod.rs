use miden_node_db::DatabaseError;

use crate::db::ReadTransaction;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the quorum registered by the operator, if any.
    pub(crate) fn select_pending_validator_quorum(&self) -> Result<Option<u16>, DatabaseError> {
        Ok(self.inner.query(SQL, &[], |row| row.get(0))?.pop())
    }
}
