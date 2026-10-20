use anyhow::Result;
use miden_node_db::migration::{SchemaHash, SchemaHashes};

use super::*;
use crate::db::queries::VALID_FOREVER;

const EXPECTED_SCHEMA_HASHES: [SchemaHash; 7] = [
    SchemaHash::from_hex("cc92cb332410e6f63036b52cf953acb446c142d5c0fbbdbd6d3b4f466510b210"),
    SchemaHash::from_hex("7c783947d0bb2c9745d28f4bdcf329f84ad970c36aa07ea85441e62718d8bbbb"),
    SchemaHash::from_hex("e026a70464e897ae9a217f45c80d72341b1bfb757200e57e41145348473a9961"),
    SchemaHash::from_hex("a581a13b00e4aa1d4539459e2b351c0585fad33c5a876f830c9b943adac92dea"),
    SchemaHash::from_hex("34bd293251a2647715dd91fa245bcd98d635e8070871b4f8335b3a3db364fc1e"),
    SchemaHash::from_hex("cce37dcaef2f20597016e89e8b3e109b486149a66f1590137c5f9b7ccc8e3ad4"),
    SchemaHash::from_hex("cce37dcaef2f20597016e89e8b3e109b486149a66f1590137c5f9b7ccc8e3ad4"),
];

#[test]
fn migration_schema_hashes_are_stable() -> Result<()> {
    let migrator = migrator()?;

    pretty_assertions::assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED_SCHEMA_HASHES));
    Ok(())
}

/// Builds a version-3 database with versioned `is_latest` rows and verifies that migration
/// `004_validity_intervals` backfills each row's `valid_until` with its successor's `block_num` (or
/// the open sentinel).
#[test]
fn migration_004_validity_intervals_backfills_valid_until() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let database_filepath = temp_dir.path().join("store.sqlite3");

    {
        let conn = rusqlite::Connection::open(&database_filepath)?;
        conn.execute_batch(include_str!("../001_initial.sql"))?;
        conn.execute_batch(include_str!("../002_index_optimizations.sql"))?;
        conn.execute_batch(include_str!("../003_block_headers_without_rowid.sql"))?;
        // One account updated at block 5, a vault key updated at block 5, a vault key written once,
        // and a storage-map key updated at block 5.
        conn.execute_batch(
            "INSERT INTO accounts \
                 (account_id, network_account_type, block_num, account_commitment, is_latest, \
                  created_at_block) \
             VALUES (X'aa', 0, 1, X'01', 0, 1), (X'aa', 0, 5, X'02', 1, 1); \
             INSERT INTO account_vault_assets \
                 (account_id, block_num, vault_key, asset, is_latest) \
             VALUES (X'aa', 1, X'0b', X'01', 0), (X'aa', 5, X'0b', X'02', 1), \
                    (X'aa', 1, X'0c', X'03', 1); \
             INSERT INTO account_storage_map_values \
                 (account_id, block_num, slot_name, key, value, is_latest) \
             VALUES (X'aa', 1, 'slot', X'0d', X'01', 0), (X'aa', 5, 'slot', X'0d', X'02', 1); \
             PRAGMA user_version = 3;",
        )?;
    }

    migrate_database(&database_filepath)?;

    let conn = rusqlite::Connection::open(&database_filepath)?;

    let accounts = conn
        .prepare("SELECT block_num, valid_until FROM accounts ORDER BY block_num ASC")?
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    pretty_assertions::assert_eq!(accounts, vec![(1, 5), (5, VALID_FOREVER)]);

    let vault = conn
        .prepare(
            "SELECT vault_key, block_num, valid_until FROM account_vault_assets \
             ORDER BY vault_key ASC, block_num ASC",
        )?
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    pretty_assertions::assert_eq!(
        vault,
        vec![
            (vec![0x0b], 1, 5),
            (vec![0x0b], 5, VALID_FOREVER),
            (vec![0x0c], 1, VALID_FOREVER),
        ]
    );

    let storage = conn
        .prepare(
            "SELECT block_num, valid_until FROM account_storage_map_values ORDER BY block_num ASC",
        )?
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    pretty_assertions::assert_eq!(storage, vec![(1, 5), (5, VALID_FOREVER)]);

    Ok(())
}
