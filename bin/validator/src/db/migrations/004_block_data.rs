use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use miden_node_db::Transaction;
use miden_node_persistence::generated::BlockStoreFormat;
use miden_node_persistence::prost::Message;
use miden_node_tracing::info;
use miden_protocol::block::{BlockHeader, SignedBlock};

/// Imports committed blocks from the block directory into the database.
///
/// Files remain untouched so a failed migration can be retried. Only blocks with committed headers
/// are imported; files left by interrupted signing attempts are not part of the validator state.
pub fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        "CREATE TABLE blocks (
            block_num BIGINT PRIMARY KEY,
            block_header BLOB NOT NULL,
            block_data BLOB NOT NULL
        ) WITHOUT ROWID;",
    )?;
    import_blocks(tx)?;
    tx.execute_batch(
        "CREATE TABLE block_transactions_new (
            block_num BIGINT NOT NULL REFERENCES blocks(block_num) ON DELETE CASCADE,
            block_tx_index BIGINT NOT NULL,
            transaction_id BLOB NOT NULL UNIQUE REFERENCES validated_transactions(id),
            PRIMARY KEY (block_num, block_tx_index)
        ) WITHOUT ROWID;",
    )?;
    copy_transaction_links(tx)?;
    tx.execute_batch(
        "DROP TABLE block_transactions;
        DROP TABLE block_headers;
        ALTER TABLE block_transactions_new RENAME TO block_transactions;",
    )?;
    Ok(())
}

/// Copies block files while retaining the original header bytes.
fn import_blocks(tx: &Transaction<'_>) -> anyhow::Result<()> {
    let total: u64 = tx.query_row("SELECT COUNT(*) FROM block_headers", [], |row| row.get(0))?;
    if total == 0 {
        return Ok(());
    }
    let database = tx.path().context("importing block files requires an on-disk database")?;
    let directory = Path::new(database)
        .parent()
        .context("database has no parent directory")?
        .join("blocks");
    let marker = fs_err::read(directory.join("format.pb"))
        .context("failed to read block store format marker")?;
    let marker =
        BlockStoreFormat::decode(marker.as_slice()).context("invalid block store format marker")?;
    ensure!(marker.version == 1, "unsupported block store version {}", marker.version);

    info!(
        target: crate::LOG_TARGET,
        "Importing blocks into SQLite",
        migration.blocks.total = total #[nonstandard]
    );
    let started = Instant::now();
    let mut last_progress = started;
    let mut imported = 0u64;
    let mut headers =
        tx.prepare("SELECT block_num, block_header FROM block_headers ORDER BY block_num")?;
    let mut rows = headers.query([])?;
    while let Some(current) = rows.next()? {
        let height = u32::try_from(current.get::<_, i64>(0)?)?;
        let header_bytes: Vec<u8> = current.get(1)?;
        let header: BlockHeader = miden_node_persistence::decode(&header_bytes)?;
        let file = directory.join(format!("{:04x}/block_{height:08x}.dat", height >> 16));
        let bytes = fs_err::read(&file)
            .with_context(|| format!("failed to read block {height} from {}", file.display()))?;
        let block: SignedBlock = miden_node_persistence::decode(&bytes)
            .with_context(|| format!("failed to decode block {height}"))?;
        ensure!(
            header.block_num().as_u32() == height && block.header() == &header,
            "block {height} does not match its committed database header"
        );
        tx.execute(
            "INSERT INTO blocks (block_num, block_header, block_data) VALUES (?1, ?2, ?3)",
            (height, header_bytes, bytes),
        )?;
        imported += 1;
        if last_progress.elapsed() >= Duration::from_secs(10) {
            info!(
                target: crate::LOG_TARGET,
                "Importing blocks into SQLite",
                migration.blocks.imported = imported #[nonstandard],
                migration.blocks.total = total #[nonstandard],
                migration.elapsed_seconds = started.elapsed().as_secs() #[nonstandard]
            );
            last_progress = Instant::now();
        }
    }
    info!(
        target: crate::LOG_TARGET,
        "Block import finished",
        migration.blocks.imported = imported #[nonstandard],
        migration.elapsed_seconds = started.elapsed().as_secs() #[nonstandard]
    );
    Ok(())
}

/// Copies transaction links in batches so long rebuilds can report progress.
///
/// Batches seek from the last copied position and remain inside the migration transaction.
fn copy_transaction_links(tx: &Transaction<'_>) -> anyhow::Result<()> {
    let total: u64 =
        tx.query_row("SELECT COUNT(*) FROM block_transactions", [], |row| row.get(0))?;
    if total == 0 {
        return Ok(());
    }
    info!(
        target: crate::LOG_TARGET,
        "Rebuilding transaction links",
        migration.transaction_links.total = total #[nonstandard]
    );
    let started = Instant::now();
    let mut last_progress = started;
    let mut copied = 0u64;
    // Block numbers and transaction indices are nonnegative.
    let mut position = (-1i64, -1i64);
    let mut copy = tx.prepare(
        "INSERT INTO block_transactions_new (block_num, block_tx_index, transaction_id)
         SELECT block_num, block_tx_index, transaction_id FROM block_transactions
         WHERE (block_num, block_tx_index) > (?1, ?2)
         ORDER BY block_num, block_tx_index
         LIMIT 10000",
    )?;
    let mut last_position = tx.prepare(
        "SELECT block_num, block_tx_index FROM block_transactions_new
         ORDER BY block_num DESC, block_tx_index DESC LIMIT 1",
    )?;
    while copied < total {
        let count = copy.execute(position)?;
        ensure!(count > 0, "transaction link copy stopped after {copied} of {total} links");
        copied += count as u64;
        position = last_position.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        if last_progress.elapsed() >= Duration::from_secs(10) {
            info!(
                target: crate::LOG_TARGET,
                "Rebuilding transaction links",
                migration.transaction_links.copied = copied #[nonstandard],
                migration.transaction_links.total = total #[nonstandard],
                migration.elapsed_seconds = started.elapsed().as_secs() #[nonstandard]
            );
            last_progress = Instant::now();
        }
    }
    info!(
        target: crate::LOG_TARGET,
        "Transaction links copied; finalizing migration",
        migration.transaction_links.copied = copied #[nonstandard],
        migration.elapsed_seconds = started.elapsed().as_secs() #[nonstandard]
    );
    Ok(())
}
