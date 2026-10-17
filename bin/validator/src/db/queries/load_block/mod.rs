//! Reads blocks from the validator database.

use miden_node_db::sqlite::ReadTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::{BlockNumber, SignedBlock};

pub fn load_block(
    tx: &ReadTx<'_>,
    block_num: BlockNumber,
) -> Result<Option<SignedBlock>, DatabaseError> {
    Ok(tx
        .query(include_str!("load_block.sql"), &[&block_num.to_raw_sql()], |row| row.get(0))?
        .into_iter()
        .next())
}
