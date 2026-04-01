use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const SQLITE_TABLES: &[&str] = &[
    "accounts",
    "block_headers",
    "notes",
    "note_scripts",
    "nullifiers",
    "transactions",
];

const SQLITE_INDEXES: &[&str] = &[
    "idx_accounts_network_prefix",
    "idx_notes_note_id",
    "idx_notes_sender",
    "idx_notes_tag",
    "idx_notes_nullifier",
    "idx_unconsumed_network_notes",
    "idx_nullifiers_prefix",
    "idx_nullifiers_block_num",
    "idx_transactions_account_id",
    "idx_transactions_block_num",
];

/// Metrics struct to show the results of the stress test
pub struct SeedingMetrics {
    insertion_time_per_block: Vec<Duration>,
    get_block_inputs_time_per_block: Vec<Duration>,
    get_batch_inputs_time_per_block: Vec<Duration>,
    bytes_per_block: Vec<usize>,
    num_insertions: u32,
    store_file_sizes: Vec<u64>,
    initial_store_size: u64,
    store_file: PathBuf,
}

impl SeedingMetrics {
    /// Creates a new Metrics instance.
    pub fn new(store_file: PathBuf) -> Self {
        let initial_store_size = get_store_size(&store_file);
        Self {
            insertion_time_per_block: Vec::new(),
            get_block_inputs_time_per_block: Vec::new(),
            get_batch_inputs_time_per_block: Vec::new(),
            bytes_per_block: Vec::new(),
            num_insertions: 0,
            store_file_sizes: Vec::new(),
            initial_store_size,
            store_file,
        }
    }

    /// Tracks a new block insertion to the metrics, with the insertion time and size of the block.
    pub fn track_block_insertion(&mut self, insertion_time: Duration, block_size: usize) {
        self.insertion_time_per_block.push(insertion_time);
        self.bytes_per_block.push(block_size);
        self.num_insertions += 1;
    }

    /// Tracks the size of the store file.
    pub fn record_store_size(&mut self) {
        self.store_file_sizes.push(get_store_size(&self.store_file));
    }

    /// Tracks the time it takes to query the block inputs.
    pub fn add_get_block_inputs(&mut self, query_time: Duration) {
        self.get_block_inputs_time_per_block.push(query_time);
    }

    /// Tracks the time it takes to query the batch inputs.
    pub fn add_get_batch_inputs(&mut self, query_time: Duration) {
        self.get_batch_inputs_time_per_block.push(query_time);
    }

    /// Prints the block metrics table.
    #[expect(clippy::cast_precision_loss)]
    fn print_block_metrics(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nBlock metrics:")?;
        writeln!(f, "Note: Each block contains 256 transactions (16 batches * 16 transactions).")?;
        writeln!(
            f,
            "The first transaction sends assets from the faucet to 255 accounts, and the remaining 255 transactions consume notes created in the previous block."
        )?;
        writeln!(
            f,
            "{:<10} {:<20} {:<30} {:<30} {:<20} {:<20}",
            "Block #",
            "Insert Time (ms)",
            "Get Block Inputs Time (ms)",
            "Get Batch Inputs Time (ms)",
            "Block Size (KB)",
            "DB Size (MB)"
        )?;
        writeln!(f, "{}", "-".repeat(135))?;
        for (i, store_size) in self.store_file_sizes.iter().enumerate() {
            let block_index = i * 50;
            let insertion_time = self
                .insertion_time_per_block
                .get(block_index)
                .unwrap_or(&Duration::default())
                .as_millis();
            let block_query_time = self
                .get_block_inputs_time_per_block
                .get(block_index)
                .unwrap_or(&Duration::default())
                .as_millis();
            let batch_query_time = self
                .get_batch_inputs_time_per_block
                .get(block_index)
                .unwrap_or(&Duration::default())
                .as_millis();
            let block_size_kb =
                *self.bytes_per_block.get(block_index).unwrap_or(&0) as f64 / 1024.0;
            let store_size_mb = *store_size as f64 / (1024.0 * 1024.0);

            writeln!(
                f,
                "{block_index:<10} {insertion_time:<20} {block_query_time:<30} {batch_query_time:<30} {block_size_kb:<20.1} {store_size_mb:<20.1}",
            )?;
        }
        Ok(())
    }

    /// Prints the database table stats.
    fn print_table_stats(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nDatabase stats:")?;
        writeln!(
            f,
            "Note: Database contains {} accounts and {} notes across all blocks.",
            self.num_insertions * 255,
            self.num_insertions * 255
        )?;
        writeln!(f, "{:<35} {:<15} {:<15}", "Table", "Size (MB)", "KB/Entry")?;
        writeln!(f, "{}", "-".repeat(70))?;
        for table in SQLITE_TABLES {
            let db_stats = Command::new("sqlite3")
                .arg(&self.store_file)
                .arg(format!(
                    "SELECT name, SUM(pgsize) AS size_bytes, (SUM(pgsize) * 1.0) / (SELECT COUNT(*) FROM {table}) AS bytes_per_row FROM dbstat WHERE name = '{table}';"
                ))
                .output()
                .expect("failed to execute process");

            let stdout = String::from_utf8(db_stats.stdout).expect("invalid utf8");
            let stats: Vec<&str> = stdout.trim_end().split('|').collect();

            let size_mb = stats.get(1).and_then(|s| s.trim().parse::<f64>().ok()).unwrap_or(0.0)
                / (1024.0 * 1024.0);
            let kb_per_entry = stats.get(2).map_or("-".to_string(), |bytes_per_entry| {
                if bytes_per_entry.trim().is_empty() {
                    "-".to_string()
                } else {
                    format!("{:.1}", bytes_per_entry.trim().parse::<f64>().unwrap_or(0.0) / 1024.0)
                }
            });

            writeln!(f, "{:<35} {:<15.1} {:<15}", stats[0], size_mb, kb_per_entry)?;
        }
        Ok(())
    }

    /// Prints the index stats.
    fn print_index_stats(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nIndex stats:")?;
        writeln!(f, "{:<35} {:<15}", "Index", "Size (MB)")?;
        writeln!(f, "{}", "-".repeat(70))?;
        for index in SQLITE_INDEXES {
            let db_stats = Command::new("sqlite3")
                .arg(&self.store_file)
                .arg(format!(
                    "SELECT name, SUM(pgsize) AS size_bytes FROM dbstat WHERE name = '{index}';"
                ))
                .output()
                .expect("failed to execute process");

            let stdout = String::from_utf8(db_stats.stdout).expect("invalid utf8");
            let stats: Vec<&str> = stdout.trim_end().split('|').collect();

            let size_mb = stats.get(1).and_then(|s| s.trim().parse::<f64>().ok()).unwrap_or(0.0)
                / (1024.0 * 1024.0);

            writeln!(f, "{:<35} {:<15.1}", stats[0], size_mb)?;
        }
        Ok(())
    }
}

impl Display for SeedingMetrics {
    #[expect(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Inserted {} blocks with avg insertion time {} ms",
            self.num_insertions,
            (self.insertion_time_per_block.iter().map(Duration::as_millis).sum::<u128>()
                / self.insertion_time_per_block.len() as u128)
        )?;
        writeln!(
            f,
            "Initial DB size: {:.1} MB",
            self.initial_store_size as f64 / (1024.0 * 1024.0)
        )?;

        // Print out the average growth rate of the store file
        let final_size = self.store_file_sizes.last().unwrap();
        let growth_rate_mb = (final_size - self.initial_store_size) as f64
            / f64::from(self.num_insertions)
            / (1024.0 * 1024.0);
        writeln!(f, "Average DB growth rate: {growth_rate_mb:.1} MB per block")?;

        // Print out the store file size every 50 blocks to track growth and performance
        self.print_block_metrics(f)?;

        // Print out the size of the tables in the store
        self.print_table_stats(f)?;

        // Print out the size of the indexes in the store
        self.print_index_stats(f)?;

        Ok(())
    }
}

/// Gets the size of the store file and its WAL file.
fn get_store_size(dump_file: &Path) -> u64 {
    let store_file_size = fs_err::metadata(dump_file).expect("Dumpfile always exists").len();
    let wal_file = format!("{}-wal", dump_file.to_str().unwrap());
    let wal_file_size = fs_err::metadata(&wal_file)
        .inspect_err(|_err| {
            eprintln!("No WAL file found: {wal_file}");
        })
        .map(|m| m.len())
        .unwrap_or_default();
    store_file_size + wal_file_size
}
