use std::num::NonZeroUsize;

use miden_protocol::transaction::TransactionId;

use super::ReadTransaction;
use crate::db::TransactionsByIdPage;
use crate::{DatabaseError, ScopedBlockNum};

impl ReadTransaction<'_> {
    /// Reads one bounded page of get transactions by id results at the requested target.
    pub fn transactions_by_id_page(
        &self,
        ids: Vec<TransactionId>,
        target: ScopedBlockNum,
        cursor: Option<TransactionId>,
        limit: NonZeroUsize,
    ) -> Result<TransactionsByIdPage, DatabaseError> {
        crate::db::queries::transactions_by_id_page(self.inner, ids, target, cursor, limit)
    }
}
