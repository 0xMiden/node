//! Bounded transaction-log lookup using the stored transaction position.

use miden_node_db::sqlite::{ReadTx, ToSqlValue};
use miden_node_proto::domain::transaction_logs::GetTransactionLogsResponse;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{LogTopic, TransactionId, TransactionLog, TransactionLogs};
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::{Felt, Word};

use crate::errors::DatabaseError;
use crate::state::ScopedBlockNum;

const SELECT_TRANSACTION: &str = include_str!("select_transaction.sql");
const SELECT_LOGS: &str = include_str!("select_log.sql");

fn corrupt() -> DatabaseError {
    DatabaseError::DataCorrupted("invalid stored transaction log collection".into())
}

/// Reads a transaction's logs up to the published tip, preserving private and empty collections.
///
/// The transaction header and ordered log rows are read from the same database snapshot.
pub(crate) fn select_transaction_logs(
    tx: &ReadTx<'_>,
    native_account_id: AccountId,
    transaction_id: TransactionId,
    tip: ScopedBlockNum,
) -> Result<Option<GetTransactionLogsResponse>, DatabaseError> {
    let header = tx
        .query(SELECT_TRANSACTION, &[&transaction_id, &native_account_id, &*tip], |row| {
            Ok((
                row.get::<BlockNumber>(0)?,
                row.get::<u32>(1)?,
                row.get::<Option<u32>>(2)?,
                row.get::<Word>(3)?,
            ))
        })?
        .into_iter()
        .next();
    let Some((block_num, transaction_index, count, logs_commitment)) = header else {
        return Ok(None);
    };
    let expected = count.unwrap_or_default() as usize;
    if native_account_id.is_public() != count.is_some() || expected > TransactionLogs::MAX_COUNT {
        return Err(corrupt());
    }
    let limit = u32::try_from(TransactionLogs::MAX_COUNT + 1).expect("log limit fits u32");
    let params: &[&dyn ToSqlValue] = &[&native_account_id, &block_num, &transaction_index, &limit];
    let rows = tx.query(SELECT_LOGS, params, |row| {
        Ok((
            row.get::<u32>(0)?,
            row.get::<TransactionId>(1)?,
            row.get::<AccountId>(2)?,
            row.get::<Vec<u8>>(3)?,
            row.get::<Vec<u8>>(4)?,
        ))
    })?;
    if rows.len() != expected {
        return Err(corrupt());
    }
    let mut logs = Vec::with_capacity(expected);
    let mut words = 0;
    for (index, (position, id, emitter, topic, content)) in rows.into_iter().enumerate() {
        if position as usize != index || id != transaction_id {
            return Err(corrupt());
        }
        let topic: [u8; 16] = topic.try_into().map_err(|_| corrupt())?;
        if content.len() % 32 != 0 || content.len() > TransactionLog::MAX_NUM_WORDS * 32 {
            return Err(corrupt());
        }
        words += content.len() / 32;
        if words > TransactionLogs::MAX_NUM_WORDS {
            return Err(corrupt());
        }
        let suffix = Felt::read_from_bytes(&topic[..8])?;
        let prefix = Felt::read_from_bytes(&topic[8..])?;
        let content = content
            .as_chunks::<32>()
            .0
            .iter()
            .map(|word| Word::read_from_bytes(word))
            .collect::<Result<Vec<_>, _>>()?;
        logs.push(TransactionLog::new(emitter, LogTopic::new(suffix, prefix), content)?);
    }
    Ok(Some(GetTransactionLogsResponse {
        transaction_id,
        native_account_id,
        block_num,
        transaction_index,
        logs_commitment,
        logs: count.is_some().then_some(logs),
    }))
}
