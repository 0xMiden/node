use miden_node_db::DatabaseError;

use crate::db::WriteTransaction;

const SQL: &str = include_str!("query.sql");

impl WriteTransaction<'_> {
    /// Stores the validator quorum registered by the operator.
    pub(crate) fn insert_pending_validator_quorum(
        &self,
        pending: u16,
    ) -> Result<(), DatabaseError> {
        self.inner.execute(SQL, &[&pending])?;
        Ok(())
    }
}
