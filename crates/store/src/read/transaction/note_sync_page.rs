use std::num::NonZeroUsize;

use super::ReadTransaction;
use crate::db::pagination::Paginated;
use crate::db::queries::NoteSyncPaged;
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
        let page = NoteSyncPaged::new(tags, range, limit).page(self.inner, &cursor)?;
        Ok(NoteSyncPage {
            notes: page.items,
            next_cursor: page.next.flatten(),
        })
    }
}
