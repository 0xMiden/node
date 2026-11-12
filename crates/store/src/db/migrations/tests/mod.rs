use anyhow::Result;
use fs_err::read;
use miden_node_db::migration::{SchemaHash, SchemaHashes};
use rusqlite::Connection;
use tempfile::tempdir;

use super::*;
use crate::db::queries::VALID_FOREVER;

const EXPECTED_SCHEMA_HASHES: [SchemaHash; 9] = [
    SchemaHash::from_hex("cc92cb332410e6f63036b52cf953acb446c142d5c0fbbdbd6d3b4f466510b210"),
    SchemaHash::from_hex("7c783947d0bb2c9745d28f4bdcf329f84ad970c36aa07ea85441e62718d8bbbb"),
    SchemaHash::from_hex("e026a70464e897ae9a217f45c80d72341b1bfb757200e57e41145348473a9961"),
    SchemaHash::from_hex("a581a13b00e4aa1d4539459e2b351c0585fad33c5a876f830c9b943adac92dea"),
    SchemaHash::from_hex("34bd293251a2647715dd91fa245bcd98d635e8070871b4f8335b3a3db364fc1e"),
    SchemaHash::from_hex("cce37dcaef2f20597016e89e8b3e109b486149a66f1590137c5f9b7ccc8e3ad4"),
    SchemaHash::from_hex("cce37dcaef2f20597016e89e8b3e109b486149a66f1590137c5f9b7ccc8e3ad4"),
    SchemaHash::from_hex("93db886dab52c2175a4572a23823fe3a05138d7f7d08ea55cd5e60ee6d4ec3a8"),
    SchemaHash::from_hex("65587acfb7f0703a16a62323008d58bfcedde7e7ff85861245d35f50f520c58a"),
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

    migrator()?.open_database(&database_filepath)?.migrate_to(4)?;

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

#[test]
fn transaction_logs_migration_rejects_populated_history_without_changes() -> Result<()> {
    let root = tempdir()?;
    let path = root.path().join("store.sqlite3");
    migrator()?.create_database(&path)?.migrate_to(8)?;
    {
        let conn = Connection::open(&path)?;
        conn.execute_batch("INSERT INTO transactions VALUES (X'01', X'02', 1, X'03', X'04', X'', X'', 0, zeroblob(32), zeroblob(32));")?;
    }
    let before = read(&path)?;
    assert!(migrate_database(&path).is_err());
    assert_eq!(read(&path)?, before);
    let conn = Connection::open(&path)?;
    assert_eq!(conn.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?, 8);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get::<_, u32>(0))?,
        1
    );
    Ok(())
}
