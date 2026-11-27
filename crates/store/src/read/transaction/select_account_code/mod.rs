use miden_protocol::Word;
use miden_protocol::account::AccountCode;

use super::ReadTransaction;
use crate::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the account code stored under `code_commitment`, or `None` if it is absent.
    pub fn select_account_code(
        &self,
        code_commitment: Word,
    ) -> Result<Option<AccountCode>, DatabaseError> {
        // `code_commitment` is the primary key, so the statement returns zero or one row.
        self.inner
            .query(SQL, &[&code_commitment], |row| row.get::<Vec<u8>>(0))?
            .into_iter()
            .next()
            .map(|bytes| miden_node_persistence::decode::<AccountCode>(&bytes))
            .transpose()
            .map_err(DatabaseError::from)
    }
}

#[cfg(test)]
mod tests;
