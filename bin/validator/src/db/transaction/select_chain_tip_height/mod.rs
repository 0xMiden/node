use miden_node_db::DatabaseError;

use super::ReadTransaction;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the stored height and number of locally signed heights, including genesis.
    pub(crate) fn signing_progress(&self) -> Result<Option<(u32, u64)>, DatabaseError> {
        let sql = include_str!("signing_progress.sql");
        Ok(self
            .inner
            .query(sql, &[], |row| Ok((row.get(0)?, u64::from(row.get::<u32>(1)?) + 1)))?
            .pop())
    }

    /// Returns the height of the latest stored block.
    pub(crate) fn select_chain_tip_height(&self) -> Result<Option<u32>, DatabaseError> {
        Ok(self.inner.query(SQL, &[], |row| row.get(0))?.pop())
    }
}
