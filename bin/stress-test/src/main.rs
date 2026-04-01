use std::path::PathBuf;

use clap::{Parser, Subcommand};
use miden_node_utils::logging::OpenTelemetry;
use seeding::seed_store;
use store::{
    bench_sync_chain_mmr,
    bench_sync_notes,
    bench_sync_nullifiers,
    bench_sync_transactions,
    load_state,
};

mod seeding;
mod store;

#[derive(Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create and store blocks into the store. Create a given number of accounts, where each
    /// account consumes a note created from a faucet.
    SeedStore {
        /// Directory in which to store the database and raw block data. If the directory contains
        /// a database dump file, it will be replaced.
        #[arg(short, long, value_name = "DATA_DIRECTORY")]
        data_directory: PathBuf,

        /// Number of accounts to create.
        #[arg(short, long, value_name = "NUM_ACCOUNTS")]
        num_accounts: usize,

        /// Percentage of accounts that will be created as public accounts. The rest will be
        /// private accounts.
        #[arg(short, long, value_name = "PUBLIC_ACCOUNTS_PERCENTAGE", default_value = "0")]
        public_accounts_percentage: u8,
    },

    /// Benchmark the performance of the store endpoints.
    BenchmarkStore {
        /// Store endpoint to test against.
        #[command(subcommand)]
        endpoint: Endpoint,

        /// Directory that contains the database dump file.
        #[arg(short, long, value_name = "DATA_DIRECTORY")]
        data_directory: PathBuf,

        /// Iterations of the sync request.
        #[arg(short, long, value_name = "ITERATIONS", default_value = "10000")]
        iterations: usize,

        /// Concurrency level of the sync request. Represents the number of request that
        /// can be sent in parallel.
        #[arg(short, long, value_name = "CONCURRENCY", default_value = "1")]
        concurrency: usize,
    },
}

#[derive(Subcommand, Clone, Copy)]
pub enum Endpoint {
    #[command(name = "sync-nullifiers")]
    SyncNullifiers {
        /// Number of prefixes to send in each request.
        #[arg(short, long, value_name = "PREFIXES", default_value = "10")]
        prefixes: usize,
    },
    #[command(name = "sync-notes")]
    SyncNotes,
    #[command(name = "sync-transactions")]
    SyncTransactions {
        /// Number of accounts to sync transactions for in each request.
        #[arg(short, long, value_name = "ACCOUNTS", default_value = "5")]
        accounts: usize,
        /// Block range size for each request (number of blocks to query).
        #[arg(short, long, value_name = "BLOCK_RANGE", default_value = "100")]
        block_range: u32,
    },
    #[command(name = "sync-chain-mmr")]
    SyncChainMmr {
        /// Block range size for each request (number of blocks to query).
        #[arg(short, long, value_name = "BLOCK_RANGE", default_value = "1000")]
        block_range: u32,
    },
    #[command(name = "load-state")]
    LoadState,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Configure tracing with optional OpenTelemetry exporting support.
    miden_node_utils::logging::setup_tracing(OpenTelemetry::Disabled).unwrap();

    match cli.command {
        Command::SeedStore {
            data_directory,
            num_accounts,
            public_accounts_percentage,
        } => {
            seed_store(data_directory, num_accounts, public_accounts_percentage).await;
        },
        Command::BenchmarkStore {
            endpoint,
            data_directory,
            iterations,
            concurrency,
        } => match endpoint {
            Endpoint::SyncNullifiers { prefixes } => {
                bench_sync_nullifiers(data_directory, iterations, concurrency, prefixes).await;
            },
            Endpoint::SyncNotes => {
                bench_sync_notes(data_directory, iterations, concurrency).await;
            },
            Endpoint::SyncTransactions { accounts, block_range } => {
                bench_sync_transactions(
                    data_directory,
                    iterations,
                    concurrency,
                    accounts,
                    block_range,
                )
                .await;
            },
            Endpoint::SyncChainMmr { block_range } => {
                bench_sync_chain_mmr(data_directory, iterations, concurrency, block_range).await;
            },
            Endpoint::LoadState => {
                load_state(&data_directory).await;
            },
        },
    }
}
