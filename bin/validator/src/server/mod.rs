use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64};

use anyhow::Context;
use miden_node_db::Db;
use miden_node_proto::generated::validator::api_server;
use miden_node_proto_build::validator_api_descriptor;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_stream::wrappers::TcpListenerStream;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use crate::db::{
    count_signed_blocks, count_validated_transactions, load_chain_tip, load_with_pool_size,
};
use crate::{COMPONENT, ValidatorSigner};

#[cfg(test)]
mod tests;

mod sign_block;
mod status;
mod submit_proven_transaction;

// VALIDATOR
// ================================================================================

/// The handle into running the gRPC validator server.
///
/// Facilitates the running of the gRPC server which implements the validator API.
pub struct Validator {
    /// The address of the validator component.
    pub address: SocketAddr,
    /// gRPC server options for internal services (timeouts, connection caps).
    ///
    /// If the handler takes longer than this duration, the server cancels the call.
    pub grpc_options: GrpcOptionsInternal,

    /// The signer used to sign blocks.
    pub signer: ValidatorSigner,

    /// The data directory for the validator component's database files.
    pub data_directory: PathBuf,

    /// Maximum number of SQLite connections in the validator database connection pool.
    pub sqlite_connection_pool_size: NonZeroUsize,
}

impl Validator {
    /// Serves the validator RPC API.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        tracing::info!(target: COMPONENT, endpoint=?self.address, "Initializing server");

        // Initialize database connection.
        let db = load_with_pool_size(
            self.data_directory.join("validator.sqlite3"),
            self.sqlite_connection_pool_size,
        )
        .await
        .context("failed to initialize validator database")?;

        // Load initial metrics from the database for the in-memory counters.
        let (initial_chain_tip, initial_tx_count, initial_block_count) = db
            .query("load_initial_metrics", |conn| {
                let tip = load_chain_tip(conn)?.expect("chain tip should exist");
                let tx_count = u64::try_from(count_validated_transactions(conn)?).unwrap_or(0);
                let block_count = u64::try_from(count_signed_blocks(conn)?).unwrap_or(0);
                Ok::<_, miden_node_db::DatabaseError>((tip, tx_count, block_count))
            })
            .await
            .context("failed to load initial metrics")?;

        // Configured signer public key must match the chain tip validator key.
        anyhow::ensure!(
            self.signer.public_key() != *initial_chain_tip.validator_key(),
            "signer public key does not match chain tip validator key"
        );

        let listener = TcpListener::bind(self.address)
            .await
            .context("failed to bind to block producer address")?;

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(validator_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        // Build the gRPC server with the API service and trace layer.
        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .timeout(self.grpc_options.request_timeout)
            .add_service(api_server::ApiServer::new(ValidatorServer::new(
                self.signer,
                db,
                initial_chain_tip.block_num().as_u32(),
                initial_tx_count,
                initial_block_count,
            )))
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .context("failed to serve validator API")
    }
}

// VALIDATOR SERVER
// ================================================================================

/// The underlying implementation of the gRPC validator server.
///
/// Implements the gRPC API for the validator.
struct ValidatorServer {
    signer: ValidatorSigner,
    db: Arc<Db>,
    /// Serializes `sign_block` requests so that concurrent calls are processed sequentially,
    /// ensuring consistent chain tip reads and preventing race conditions.
    sign_block_semaphore: Semaphore,
    /// In-memory chain tip, updated atomically after each signed block.
    chain_tip: AtomicU32,
    /// In-memory count of validated transactions, incremented after each new insert.
    validated_transactions_count: AtomicU64,
    /// In-memory count of signed blocks, incremented after each signed block.
    signed_blocks_count: AtomicU64,
}

impl ValidatorServer {
    fn new(
        signer: ValidatorSigner,
        db: Db,
        initial_chain_tip: u32,
        initial_tx_count: u64,
        initial_block_count: u64,
    ) -> Self {
        Self {
            signer,
            db: db.into(),
            sign_block_semaphore: Semaphore::new(1),
            chain_tip: AtomicU32::new(initial_chain_tip),
            validated_transactions_count: AtomicU64::new(initial_tx_count),
            signed_blocks_count: AtomicU64::new(initial_block_count),
        }
    }
}
