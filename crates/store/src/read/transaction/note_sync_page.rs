use std::num::NonZeroUsize;

use super::ReadTransaction;
use crate::{DatabaseError, NoteSyncCursor, NoteSyncPage, ScopedBlockRange};

impl ReadTransaction<'_> {
    /// Reads one bounded page of sync notes results at the requested target.
    pub fn note_sync_page(
        &self,
        tags: Vec<u32>,
        range: ScopedBlockRange,
        cursor: Option<NoteSyncCursor>,
        limit: NonZeroUsize,
    ) -> Result<NoteSyncPage, DatabaseError> {
        crate::db::queries::note_sync_page(self.inner, tags, range, cursor, limit)
    }
}
