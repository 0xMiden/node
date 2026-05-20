//! Runs benchmarks.
//!
//! Each subcommand's body lives in its own module (`create_proofs`, `submit`).
//! `main.rs` is just the clap CLI + dispatch + a few shared utilities both
//! orchestrators need (RPC client setup with genesis metadata, file I/O
//! helpers, and the proofs-bundle directory).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use url::Url;

mod create_proofs;
mod inclusion;
mod prover;
mod rpc_state;
mod submit;
mod summary;

// SHARED CONSTANTS
// ================================================================================================

pub(crate) const PROOFS_DIR: &str = "./benchmark-proofs";

// COMMANDS
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    CreateProofs {
        /// RPC endpoint of the target miden node — used to discover the genesis commitment that the
        /// generated proofs are bound to. Must match the node you intend to submit the proofs
        /// against.
        #[arg(long, default_value = "http://127.0.0.1:57291")]
        rpc_url: Url,
        /// Number of mint + consume transaction pairs to generate. Each pair takes seconds of real
        /// STARK proving, so start small.
        #[arg(long, default_value_t = 10)]
        num_transactions: u64,
        /// If set, proofs are produced by the remote prover at this URL instead of locally.
        /// Dispatch is rate-limited: starts at 1 req/s, bumps by 1 req/s every 3 minutes up to 10
        /// req/s, and freezes at the current step if the prover returns a retryable error
        /// (resource-exhausted, unavailable, or deadline-exceeded). If unset, proving runs locally
        /// with `LocalTransactionProver`.
        #[arg(long)]
        remote_prover_url: Option<String>,
    },
    RunBenchmark {
        /// RPC endpoint of the target miden node.
        #[arg(long, default_value = "http://127.0.0.1:57291")]
        rpc_url: Url,
        /// Number of concurrent submission tasks.
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        /// Maximum number of blocks past the submission point to scan before giving up. The scan
        /// exits early as soon as every submitted tx has been seen on-chain, so this is an upper
        /// bound on the wait, not a fixed delay. Bump this when running large batches that may take
        /// many blocks to fully include.
        #[arg(long, default_value_t = 30)]
        wait_blocks: u32,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    cli.run().await;
}

impl Cli {
    async fn run(self) {
        match self.command {
            Command::CreateProofs {
                rpc_url,
                num_transactions,
                remote_prover_url,
            } => {
                create_proofs::run(rpc_url, num_transactions, remote_prover_url).await;
            },
            Command::RunBenchmark { rpc_url, concurrency, wait_blocks } => {
                submit::run(rpc_url, concurrency, wait_blocks).await;
            },
        }
    }
}

// SHARED INFRA
// ================================================================================================

/// Create an RPC client configured with the correct genesis metadata in the `Accept` header so that
/// write RPCs such as `SubmitProvenTransaction` are accepted by the node.
pub(crate) async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<RpcClient> {
    let use_tls = rpc_url.scheme() == "https";

    let tls_stage = Builder::new(rpc_url.clone());
    let timeout_stage = if use_tls {
        tls_stage.with_tls().context("Failed to configure TLS for RPC client")?
    } else {
        tls_stage.without_tls()
    };
    let mut rpc: RpcClient = timeout_stage
        .with_timeout(timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to create RPC client for genesis discovery")?;

    let response = rpc
        .get_block_header_by_number(get_genesis_header_request())
        .await
        .context("Failed to get genesis block header from RPC")?
        .into_inner();

    let genesis_block_header = response
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    let genesis_header: BlockHeader =
        genesis_block_header.try_into().context("Failed to convert block header")?;

    let genesis_commitment = genesis_header.commitment();
    let genesis = genesis_commitment.to_hex();

    let tls_stage = Builder::new(rpc_url.clone());
    let timeout_stage = if use_tls {
        tls_stage.with_tls().context("Failed to configure TLS for RPC client")?
    } else {
        tls_stage.without_tls()
    };
    let rpc_client = timeout_stage
        .with_timeout(timeout)
        .without_metadata_version()
        .with_metadata_genesis(genesis)
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to connect to RPC server with genesis metadata")?;

    Ok(rpc_client)
}

pub(crate) fn get_genesis_header_request() -> BlockHeaderByNumberRequest {
    BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    }
}

pub(crate) fn read_from_file<T: Deserializable>(path: &Path) -> T {
    let bytes = fs_err::read(path).unwrap_or_else(|_| {
        panic!("failed to read {} — run `create-proofs` first", path.display())
    });
    T::read_from_bytes(&bytes)
        .unwrap_or_else(|_| panic!("failed to deserialize {}", path.display()))
}

pub(crate) fn write_to_file<T: Serializable>(path: &Path, value: &T) {
    fs_err::write(path, value.to_bytes())
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}
