use std::num::NonZeroUsize;

use miden_protocol::account::AccountId;

use super::ReadTransaction;
use crate::db::TransactionRecordsPage;
use crate::{DatabaseError, ScopedBlockRange, TransactionCursor};

impl ReadTransaction<'_> {
    /// Reads one bounded page of sync transactions results at the requested target.
    pub fn transaction_records_page(
        &self,
        ids: Vec<AccountId>,
        range: ScopedBlockRange,
        cursor: Option<TransactionCursor>,
        limit: NonZeroUsize,
    ) -> Result<TransactionRecordsPage, DatabaseError> {
        crate::db::queries::transaction_records_page(self.inner, ids, range, cursor, limit)
    }
}
