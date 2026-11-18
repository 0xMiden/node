use miden_protocol::Word;
use miden_protocol::account::AccountCode;

use super::ReadTransaction;
use crate::DatabaseError;

impl ReadTransaction<'_> {
    /// Returns the account code with the given commitment, or `None` if no account uses it.
    pub fn select_account_code(
        &self,
        code_commitment: Word,
    ) -> Result<Option<AccountCode>, DatabaseError> {
        crate::db::queries::select_account_code_by_commitment(self.inner, code_commitment)?
            .map(|bytes| miden_node_persistence::decode::<AccountCode>(&bytes))
            .transpose()
            .map_err(DatabaseError::from)
    }
}
