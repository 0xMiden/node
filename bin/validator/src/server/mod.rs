use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::server::validator_api;
use miden_node_proto_build::validator_api_descriptor;
use miden_node_store::BlockStore;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use url::Url;

use crate::db::{
    count_signed_blocks,
    count_validated_transactions,
    load_chain_tip,
    load_with_pool_size,
};
use crate::{COMPONENT, DataDirectory, ValidatorSigner};

mod validator_service;

use validator_service::ValidatorService;

// VALIDATOR SERVER
// ================================================================================

/// The handle into running the gRPC validator server.
///
/// Facilitates the running of the gRPC server which implements the validator API.
pub struct ValidatorServer {
    /// The address of the validator component.
    pub address: SocketAddr,

    /// The URL of the standby validator.
    pub standby_validator_url: Option<Url>,

    /// gRPC server options for internal services (timeouts, connection caps).
    ///
    /// If the handler takes longer than this duration, the server cancels the call.
    pub grpc_options: GrpcOptionsInternal,

    /// The signer used to sign blocks.
    pub signer: ValidatorSigner,

    /// The data directory for the validator component's database files.
    pub data_directory: DataDirectory,

    /// Maximum number of SQLite connections in the validator database connection pool.
    pub sqlite_connection_pool_size: NonZeroUsize,
}

impl ValidatorServer {
    /// Serves the validator RPC API.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        tracing::info!(target: COMPONENT, endpoint=?self.address, "Initializing server");

        // Initialize database connection.
        let db = load_with_pool_size(
            self.data_directory.database_path(),
            self.sqlite_connection_pool_size,
        )
        .await
        .context("failed to initialize validator database")?;

        // Initialize block store.
        let block_store = BlockStore::load(self.data_directory.block_store_dir())
            .context("failed to load block store")?;

        // Load initial metrics from the database for the in-memory counters.
        let (initial_chain_tip, initial_tx_count, initial_block_count) = db
            .query("load_initial_metrics", |conn| {
                let tip = load_chain_tip(conn)?.map_or(0, |h| h.block_num().as_u32());
                let tx_count = u64::try_from(count_validated_transactions(conn)?).unwrap_or(0);
                let block_count = u64::try_from(count_signed_blocks(conn)?).unwrap_or(0);
                Ok::<_, miden_node_db::DatabaseError>((tip, tx_count, block_count))
            })
            .await
            .context("failed to load initial metrics")?;

        let listener = TcpListener::bind(self.address)
            .await
            .context("failed to bind to block producer address")?;

        let standby = self.standby_validator_url.map(|url| {
            Builder::new(url)
                .with_tls()
                .expect("trusted certs should be available")
                .with_timeout(Duration::from_secs(5))
                .without_metadata_version()
                .without_metadata_genesis()
                .with_otel_context_injection()
                .connect_lazy::<ValidatorClient>()
        });

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(validator_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        // Build the gRPC server with the API service and trace layer.
        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .timeout(self.grpc_options.request_timeout)
            .add_service(validator_api::service(
                ValidatorService::new(
                    self.signer,
                    db,
                    block_store,
                    initial_chain_tip,
                    initial_tx_count,
                    initial_block_count,
                    standby,
                )
                .await
                .context("failed to initialize validator server")?,
            ))
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .context("failed to serve validator API")
    }
}
