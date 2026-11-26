use std::num::NonZeroUsize;

use super::ReadTransaction;
use crate::db::NullifierUpdatesPage;
use crate::{DatabaseError, NullifierCursor, ScopedBlockRange};

impl ReadTransaction<'_> {
    /// Reads one bounded page of sync nullifiers results at the requested target.
    pub fn nullifier_updates_page(
        &self,
        prefixes: Vec<u16>,
        range: ScopedBlockRange,
        cursor: Option<NullifierCursor>,
        limit: NonZeroUsize,
    ) -> Result<NullifierUpdatesPage, DatabaseError> {
        crate::db::queries::nullifier_updates_page(self.inner, prefixes, range, cursor, limit)
    }
}
