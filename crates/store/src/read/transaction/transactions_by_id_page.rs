use std::num::NonZeroUsize;

use miden_protocol::transaction::TransactionId;

use super::ReadTransaction;
use crate::db::TransactionsByIdPage;
use crate::db::pagination::Paginated;
use crate::db::queries::TransactionsById;
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
        let page = TransactionsById::new(ids, target, limit).page(self.inner, &cursor)?;
        Ok(TransactionsByIdPage {
            records: page.items,
            next_cursor: page.next.flatten(),
        })
    }
}
