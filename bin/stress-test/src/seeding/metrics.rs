use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockKind {
    AccountNoteEmission,
    AccountCreation,
    UpdateNoteEmission,
    AccountUpdate,
}

impl Display for BlockKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::AccountNoteEmission => "account-note-emission",
            Self::AccountCreation => "account-creation",
            Self::UpdateNoteEmission => "update-note-emission",
            Self::AccountUpdate => "account-update",
        };
        f.pad(name)
    }
}

struct BlockMetric {
    kind: BlockKind,
    insertion_time: Duration,
    get_block_inputs_time: Duration,
    block_size: usize,
    transaction_count: usize,
    public_account_updates: usize,
}

/// Metrics struct to show the results of the stress test
pub struct SeedingMetrics {
    blocks: Vec<BlockMetric>,
    pending_get_block_inputs_time: Option<Duration>,
    get_note_inclusion_proofs_time_per_block: Vec<Duration>,
    store_file_sizes: Vec<(usize, u64)>,
    initial_store_size: u64,
    store_file: PathBuf,
}

impl SeedingMetrics {
    /// Creates a new Metrics instance.
    pub fn new(store_file: PathBuf) -> Self {
        let initial_store_size = get_store_size(&store_file);
        Self {
            blocks: Vec::new(),
            pending_get_block_inputs_time: None,
            get_note_inclusion_proofs_time_per_block: Vec::new(),
            store_file_sizes: Vec::new(),
            initial_store_size,
            store_file,
        }
    }

    /// Tracks a new block insertion to the metrics, with the insertion time and size of the block.
    pub fn track_block_insertion(
        &mut self,
        kind: BlockKind,
        insertion_time: Duration,
        block_size: usize,
        transaction_count: usize,
        public_account_updates: usize,
    ) {
        self.blocks.push(BlockMetric {
            kind,
            insertion_time,
            get_block_inputs_time: self.pending_get_block_inputs_time.take().unwrap_or_default(),
            block_size,
            transaction_count,
            public_account_updates,
        });
    }

    /// Tracks the size of the store file.
    pub fn record_store_size(&mut self) {
        if let Some(block_index) = self.blocks.len().checked_sub(1) {
            self.store_file_sizes.push((block_index, get_store_size(&self.store_file)));
        }
    }

    /// Tracks the time it takes to query the block inputs.
    pub fn add_get_block_inputs(&mut self, query_time: Duration) {
        assert!(
            self.pending_get_block_inputs_time.replace(query_time).is_none(),
            "block input query time should be consumed before the next query"
        );
    }

    /// Tracks the time it takes to query the note inclusion proofs.
    pub fn add_get_note_inclusion_proofs(&mut self, query_time: Duration) {
        self.get_note_inclusion_proofs_time_per_block.push(query_time);
    }

    /// Prints the block metrics table.
    #[expect(clippy::cast_precision_loss)]
    fn print_block_metrics(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nBlock metrics:")?;
        writeln!(
            f,
            "{:<10} {:<24} {:<8} {:<16} {:<18} {:<24} {:<16} {:<16}",
            "Block #",
            "Kind",
            "Txs",
            "Public updates",
            "Insert time (ms)",
            "Get block inputs (ms)",
            "Block Size (KB)",
            "DB Size (MB)"
        )?;
        writeln!(f, "{}", "-".repeat(150))?;
        for (block_index, metric) in self.blocks.iter().enumerate().filter(|(index, metric)| {
            self.blocks.len() <= 20
                || index % 50 == 0
                || index + 1 == self.blocks.len()
                || metric.kind == BlockKind::AccountUpdate
        }) {
            let block_size_kb = metric.block_size as f64 / 1024.0;
            let store_size_mb =
                self.store_file_sizes.iter().rev().find_map(|(sample_index, size)| {
                    (*sample_index == block_index).then_some(*size as f64 / (1024.0 * 1024.0))
                });
            let store_size =
                store_size_mb.map_or_else(|| "-".to_string(), |size| format!("{size:.1}"));

            writeln!(
                f,
                "{block_index:<10} {:<24} {:<8} {:<16} {:<18} {:<24} {block_size_kb:<16.1} {store_size:<16}",
                metric.kind,
                metric.transaction_count,
                metric.public_account_updates,
                metric.insertion_time.as_millis(),
                metric.get_block_inputs_time.as_millis(),
            )?;
        }

        if !self.get_note_inclusion_proofs_time_per_block.is_empty() {
            let average = self
                .get_note_inclusion_proofs_time_per_block
                .iter()
                .map(Duration::as_micros)
                .sum::<u128>()
                / self.get_note_inclusion_proofs_time_per_block.len() as u128;
            writeln!(f, "Average get-note-inclusion-proofs time: {average} us")?;
        }
        Ok(())
    }

    /// Prints the database table stats.
    fn print_table_stats(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nDatabase stats:")?;
        let account_count = self.table_row_count("accounts");
        let note_count = self.table_row_count("notes");
        if let (Some(account_count), Some(note_count)) = (account_count, note_count) {
            writeln!(
                f,
                "Note: Database contains {account_count} accounts and {note_count} notes across all blocks."
            )?;
        }
        writeln!(f, "{:<55} {:<15} {:<15}", "Table", "Size (MB)", "KB/Entry")?;
        writeln!(f, "{}", "-".repeat(85))?;
        for table in self.schema_object_names("table") {
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

            writeln!(f, "{:<55} {:<15.1} {:<15}", stats[0], size_mb, kb_per_entry)?;
        }
        Ok(())
    }

    /// Lists the names of the tables or indexes in the store, so the stats stay in sync with the
    /// schema instead of relying on a hardcoded list.
    fn schema_object_names(&self, kind: &str) -> Vec<String> {
        let output = Command::new("sqlite3")
            .arg(&self.store_file)
            .arg(format!(
                "SELECT name FROM sqlite_master WHERE type = '{kind}' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
            ))
            .output()
            .expect("failed to execute process");
        String::from_utf8(output.stdout)
            .expect("invalid utf8")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn table_row_count(&self, table: &str) -> Option<u64> {
        let output = Command::new("sqlite3")
            .arg(&self.store_file)
            .arg(format!("SELECT COUNT(*) FROM {table};"))
            .output()
            .ok()?;
        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    }

    /// Prints the index stats.
    fn print_index_stats(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nIndex stats:")?;
        writeln!(f, "{:<55} {:<15}", "Index", "Size (MB)")?;
        writeln!(f, "{}", "-".repeat(85))?;
        for index in self.schema_object_names("index") {
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

            writeln!(f, "{:<55} {:<15.1}", stats[0], size_mb)?;
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
            self.blocks.len(),
            self.blocks.iter().map(|metric| metric.insertion_time.as_millis()).sum::<u128>()
                / self.blocks.len().max(1) as u128
        )?;
        writeln!(
            f,
            "Initial DB size: {:.1} MB",
            self.initial_store_size as f64 / (1024.0 * 1024.0)
        )?;

        // Print out the average growth rate of the store file
        let final_size = self
            .store_file_sizes
            .last()
            .map_or_else(|| get_store_size(&self.store_file), |(_, size)| *size);
        let growth_rate_mb = final_size.saturating_sub(self.initial_store_size) as f64
            / self.blocks.len().max(1) as f64
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
