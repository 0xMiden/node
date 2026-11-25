use std::num::NonZeroUsize;

use super::ReadTransaction;
use crate::db::NullifierUpdatesPage;
use crate::db::pagination::Paginated;
use crate::db::queries::NullifierUpdatesPaged;
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
        let page = NullifierUpdatesPaged::new(prefixes, range, limit).page(self.inner, &cursor)?;
        Ok(NullifierUpdatesPage {
            records: page.items,
            next_cursor: page.next.flatten(),
        })
    }
}
