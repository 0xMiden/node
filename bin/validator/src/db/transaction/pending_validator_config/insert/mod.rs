use miden_node_db::DatabaseError;
use miden_protocol::block::ValidatorConfig;

use crate::db::WriteTransaction;

const SQL: &str = include_str!("query.sql");

impl WriteTransaction<'_> {
    /// Stores the validator configuration registered by the operator.
    pub(crate) fn insert_pending_validator_config(
        &self,
        pending: &ValidatorConfig,
    ) -> Result<(), DatabaseError> {
        self.inner.execute(SQL, &[pending])?;
        Ok(())
    }
}
