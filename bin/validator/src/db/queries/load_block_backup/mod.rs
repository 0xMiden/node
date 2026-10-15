//! Reads signed blocks together with their retained proving material.
use miden_node_db::sqlite::ReadTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_node_proto::BlockProofRequest;
use miden_protocol::block::{BlockNumber, SignedBlock};

use crate::db::BlockBackup;

pub fn load_block_backup(
    tx: &ReadTx<'_>,
    block_num: BlockNumber,
) -> Result<Option<BlockBackup>, DatabaseError> {
    let rows =
        tx.query(include_str!("load_block_backup.sql"), &[&block_num.to_raw_sql()], |row| {
            Ok((row.get::<SignedBlock>(0)?, row.get::<Option<Vec<u8>>>(1)?))
        })?;
    rows.into_iter()
        .next()
        .map(|(block, bytes)| {
            let proving_inputs = bytes
                .map(|bytes| {
                    miden_node_persistence::decode::<BlockProofRequest>(&bytes)
                        .map_err(|error| DatabaseError::deserialization("BlockProofRequest", error))
                })
                .transpose()?;
            if let Some(inputs) = &proving_inputs {
                inputs
                    .validate_against(&block)
                    .map_err(|error| DatabaseError::deserialization("BlockProofRequest", error))?;
            }
            Ok(BlockBackup { block, proving_inputs })
        })
        .transpose()
}
