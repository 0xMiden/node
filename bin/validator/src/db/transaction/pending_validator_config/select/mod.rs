use miden_node_db::DatabaseError;
use miden_protocol::block::ValidatorConfig;

use crate::db::ReadTransaction;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the configuration registered by the operator, if any.
    pub(crate) fn select_pending_validator_config(
        &self,
    ) -> Result<Option<ValidatorConfig>, DatabaseError> {
        Ok(self.inner.query(SQL, &[], |row| row.get(0))?.pop())
    }
}
