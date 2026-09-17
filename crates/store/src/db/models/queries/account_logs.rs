use std::ops::RangeInclusive;

use diesel::prelude::*;
use diesel::sql_types::{BigInt, Binary};
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockBody, BlockNumber};
use miden_protocol::transaction::{LogTopic, TransactionId, TransactionLog, TransactionLogData};
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::DatabaseError;

pub const MAX_ACCOUNT_LOG_PAGE_SIZE: u32 = 256;
pub const MAX_ACCOUNT_LOG_PAGE_BYTES: usize = 1024 * 1024;

/// Position of a log in the committed chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountLogCursor {
    pub block_num: BlockNumber,
    pub transaction_index: u32,
    pub log_index: u32,
}

/// A public log and its transaction position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLogRecord {
    pub cursor: AccountLogCursor,
    pub transaction_id: TransactionId,
    pub native_account_id: AccountId,
    pub log: TransactionLog,
}

#[derive(Clone, Debug)]
pub struct AccountLogPage {
    pub records: Vec<AccountLogRecord>,
    /// Resume after this position with the same account, range, and topic.
    pub next_cursor: Option<AccountLogCursor>,
}

#[derive(QueryableByName)]
struct RawLog {
    #[diesel(sql_type = BigInt)]
    block_num: i64,
    #[diesel(sql_type = BigInt)]
    transaction_index: i64,
    #[diesel(sql_type = BigInt)]
    log_index: i64,
    #[diesel(sql_type = Binary)]
    native_account_id: Vec<u8>,
    #[diesel(sql_type = Binary)]
    transaction_id: Vec<u8>,
    #[diesel(sql_type = Binary)]
    record: Vec<u8>,
}

pub(crate) fn insert_account_logs(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    body: &BlockBody,
) -> Result<usize, DatabaseError> {
    body.log_data()
        .validate_for_block(body.transactions())
        .map_err(|error| DatabaseError::DataCorrupted(error.to_string()))?;
    let mut count = 0;
    for (transaction_index, (header, data)) in body
        .transactions()
        .as_slice()
        .iter()
        .zip(body.log_data().as_slice())
        .enumerate()
    {
        let TransactionLogData::Public(logs) = data else {
            continue;
        };
        for (log_index, log) in logs.iter().enumerate() {
            count += diesel::sql_query("INSERT INTO account_logs (emitter_account_id, block_num, transaction_index, log_index, topic, native_account_id, transaction_id, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                .bind::<Binary, _>(log.emitter().to_bytes())
                .bind::<BigInt, _>(i64::from(block_num.as_u32()))
                .bind::<BigInt, _>(i64::try_from(transaction_index).expect("bounded transaction index"))
                .bind::<BigInt, _>(i64::try_from(log_index).expect("bounded log index"))
                .bind::<Binary, _>(log.topic().to_bytes())
                .bind::<Binary, _>(header.account_id().to_bytes())
                .bind::<Binary, _>(header.id().to_bytes())
                .bind::<Binary, _>(log.to_bytes())
                .execute(conn)?;
        }
    }
    Ok(count)
}

/// Returns a bounded page from one emitter account. The cursor can resume within a block.
pub fn select_account_logs(
    conn: &mut SqliteConnection,
    account: AccountId,
    range: RangeInclusive<BlockNumber>,
    topic: Option<LogTopic>,
    after: Option<AccountLogCursor>,
    limit: u32,
) -> Result<AccountLogPage, DatabaseError> {
    if range.is_empty()
        || limit == 0
        || limit > MAX_ACCOUNT_LOG_PAGE_SIZE
        || after.is_some_and(|cursor| {
            !range.contains(&cursor.block_num)
                || cursor.log_index as usize >= miden_protocol::MAX_LOGS_PER_TX
                || cursor.transaction_index as usize
                    >= miden_protocol::MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK
        })
    {
        return Err(DatabaseError::InvalidAccountLogQuery);
    }
    let mut sql = String::from(
        "SELECT block_num, transaction_index, log_index, native_account_id, transaction_id, record FROM account_logs WHERE emitter_account_id = ? AND block_num >= ? AND block_num <= ? AND (block_num, transaction_index, log_index) > (?, ?, ?)",
    );
    if topic.is_some() {
        sql = sql.replace(
            "FROM account_logs WHERE",
            "FROM account_logs INDEXED BY account_logs_topic WHERE",
        );
        sql.push_str(" AND topic = ?");
    }
    sql.push_str(" ORDER BY block_num, transaction_index, log_index LIMIT ?");
    let mut query = diesel::sql_query(sql)
        .into_boxed::<diesel::sqlite::Sqlite>()
        .bind::<Binary, _>(account.to_bytes())
        .bind::<BigInt, _>(i64::from(range.start().as_u32()))
        .bind::<BigInt, _>(i64::from(range.end().as_u32()))
        .bind::<BigInt, _>(i64::from(
            after.map_or(*range.start(), |cursor| cursor.block_num).as_u32(),
        ))
        .bind::<BigInt, _>(after.map_or(-1, |cursor| i64::from(cursor.transaction_index)))
        .bind::<BigInt, _>(after.map_or(-1, |cursor| i64::from(cursor.log_index)));
    if let Some(topic) = topic {
        query = query.bind::<Binary, _>(topic.to_bytes());
    }
    // At most 257 records of at most 8 KiB are loaded, including the lookahead record.
    let rows = query.bind::<BigInt, _>(i64::from(limit) + 1).load::<RawLog>(conn)?;
    let mut records = Vec::new();
    let mut bytes = 0;
    let mut next_cursor = None;
    for row in rows {
        if records.len() >= limit as usize
            || bytes + row.record.len() + 192 > MAX_ACCOUNT_LOG_PAGE_BYTES
        {
            next_cursor = records.last().map(|record: &AccountLogRecord| record.cursor);
            break;
        }
        bytes += row.record.len() + 192;
        let log = TransactionLog::read_from_bytes(&row.record)?;
        if log.emitter() != account || topic.is_some_and(|topic| log.topic() != topic) {
            return Err(DatabaseError::DataCorrupted("log index does not match record".into()));
        }
        let cursor = AccountLogCursor {
            block_num: u32::try_from(row.block_num)
                .map_err(|_| DatabaseError::DataCorrupted("invalid log block".into()))?
                .into(),
            transaction_index: u32::try_from(row.transaction_index)
                .map_err(|_| DatabaseError::DataCorrupted("invalid transaction index".into()))?,
            log_index: u32::try_from(row.log_index)
                .map_err(|_| DatabaseError::DataCorrupted("invalid log index".into()))?,
        };
        records.push(AccountLogRecord {
            cursor,
            log,
            transaction_id: TransactionId::read_from_bytes(&row.transaction_id)?,
            native_account_id: AccountId::read_from_bytes(&row.native_account_id)?,
        });
    }
    Ok(AccountLogPage { records, next_cursor })
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::block::{BlockHeader, BlockSignatures};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    };
    use miden_protocol::transaction::{
        InputNotes,
        OrderedTransactionHeaders,
        TransactionHeader,
        TransactionLogDataCollection,
        TransactionLogs,
    };

    use super::*;

    fn seed(
        conn: &mut SqliteConnection,
        block: u32,
        count: u32,
        logs_per_tx: usize,
        words: usize,
    ) -> (AccountId, AccountId) {
        let native: AccountId =
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
        let emitter: AccountId =
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap();
        let private: AccountId = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
        let block_num = block.into();
        super::super::insert_block_header(
            conn,
            &BlockHeader::mock(block, None, None, &[]),
            &BlockSignatures::new(vec![]).unwrap(),
        )
        .unwrap();
        let mut headers = Vec::new();
        let mut data = Vec::new();
        for index in 0..count {
            let logs = TransactionLogs::new(
                (0..logs_per_tx)
                    .map(|log_index| {
                        let topic = LogTopic::from_name(if log_index % 2 == 0 {
                            "test::even"
                        } else {
                            "test::odd"
                        });
                        TransactionLog::new(emitter, topic, vec![Word::from([71u32; 4]); words])
                            .unwrap()
                    })
                    .collect(),
            )
            .unwrap();
            let entry = TransactionLogData::Public(logs);
            let state = block * 1000 + index;
            headers.push(
                TransactionHeader::new(
                    native,
                    Word::from([state; 4]),
                    Word::from([state + 1; 4]),
                    InputNotes::default(),
                    vec![],
                    entry.commitment(),
                )
                .unwrap(),
            );
            data.push(entry);
        }
        let entry = TransactionLogData::Private(Word::from([block; 4]));
        headers.push(
            TransactionHeader::new(
                private,
                Word::from([block + 100; 4]),
                Word::from([block + 101; 4]),
                InputNotes::default(),
                vec![],
                entry.commitment(),
            )
            .unwrap(),
        );
        data.push(entry);
        let body = BlockBody::new(
            vec![],
            vec![],
            vec![],
            TransactionLogDataCollection::new(data).unwrap(),
            OrderedTransactionHeaders::new_unchecked(headers),
        )
        .unwrap();
        super::super::insert_transactions(conn, block_num, body.transactions()).unwrap();
        assert_eq!(
            insert_account_logs(conn, block_num, &body).unwrap(),
            count as usize * logs_per_tx
        );
        (native, emitter)
    }

    #[test]
    fn account_logs_page_inside_blocks_and_filter_by_emitter_and_topic() {
        let mut conn = crate::db::migrations::test_connection();
        let (native, emitter) = seed(&mut conn, 1, 3, 64, 0);
        seed(&mut conn, 2, 3, 64, 0);
        let range = BlockNumber::from(1)..=BlockNumber::from(2);
        let mut cursor = None;
        let mut records = Vec::new();
        loop {
            let page =
                select_account_logs(&mut conn, emitter, range.clone(), None, cursor, 7).unwrap();
            assert!(page.records.len() <= 7);
            records.extend(page.records);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(records.len(), 384);
        assert!(records.windows(2).all(|pair| pair[0].cursor < pair[1].cursor));
        assert!(records.iter().all(|record| record.native_account_id == native && record.log.emitter() == emitter));
        assert!(
            select_account_logs(&mut conn, native, range.clone(), None, None, 256)
                .unwrap()
                .records
                .is_empty()
        );
        assert!(
            select_account_logs(
                &mut conn,
                ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
                range.clone(),
                None,
                None,
                256
            )
            .unwrap()
            .records
            .is_empty()
        );
        let even = LogTopic::from_name("test::even");
        let page =
            select_account_logs(&mut conn, emitter, range.clone(), Some(even), None, 256).unwrap();
        assert_eq!(page.records.len(), 192);
        assert!(page.next_cursor.is_none());
        assert!(page.records.iter().all(|record| record.log.topic() == even));
        assert!(select_account_logs(&mut conn, emitter, range, None, None, 257).is_err());
    }

    #[test]
    fn account_logs_enforce_the_byte_budget_and_keep_the_next_record() {
        let mut conn = crate::db::migrations::test_connection();
        let (_, emitter) = seed(&mut conn, 1, 150, 1, 256);
        let range = BlockNumber::from(1)..=BlockNumber::from(1);
        let first =
            select_account_logs(&mut conn, emitter, range.clone(), None, None, 256).unwrap();
        assert!(first.records.len() < 150);
        assert!(
            first
                .records
                .iter()
                .map(|record| record.log.to_bytes().len() + 192)
                .sum::<usize>()
                <= MAX_ACCOUNT_LOG_PAGE_BYTES
        );
        let second = select_account_logs(
            &mut conn,
            emitter,
            range,
            None,
            Some(first.next_cursor.unwrap()),
            256,
        )
        .unwrap();
        assert_eq!(first.records.len() + second.records.len(), 150);
        assert!(first.records.last().unwrap().cursor < second.records[0].cursor);
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn account_logs_queries_use_account_leading_indexes() {
        #[derive(QueryableByName)]
        struct Plan {
            #[diesel(sql_type = diesel::sql_types::Text)]
            detail: String,
        }
        let mut conn = crate::db::migrations::test_connection();
        for (filter, expected) in
            [("", "PRIMARY KEY"), (" AND topic = X'01'", "account_logs_topic")]
        {
            let index = if filter.is_empty() {
                ""
            } else {
                "INDEXED BY account_logs_topic"
            };
            let plan = diesel::sql_query(format!("EXPLAIN QUERY PLAN SELECT record FROM account_logs {index} WHERE emitter_account_id = X'01' AND block_num >= 1 AND block_num <= 10{filter} AND (block_num, transaction_index, log_index) > (1, 1, 1) ORDER BY block_num, transaction_index, log_index LIMIT 257")).load::<Plan>(&mut conn).unwrap();
            assert!(
                plan.iter().any(|line| line.detail.contains(expected)),
                "{:?}",
                plan.iter().map(|line| &line.detail).collect::<Vec<_>>()
            );
            assert!(plan.iter().all(|line| !line.detail.contains("SCAN account_logs")
                && !line.detail.contains("TEMP B-TREE")));
        }
    }
}
