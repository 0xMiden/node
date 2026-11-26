use miden_node_db::DatabaseError;

use crate::db::WriteTransaction;

const SQL: &str = include_str!("query.sql");

impl WriteTransaction<'_> {
    /// Deletes the pending validator quorum.
    pub(crate) fn delete_pending_validator_quorum(&self) -> Result<(), DatabaseError> {
        self.inner.execute(SQL, &[])?;
        Ok(())
    }
}
