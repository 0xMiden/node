use std::net::SocketAddr;

use anyhow::Context;
use miden_node_proto::server::validator_api;
use miden_node_proto_build::validator_api_descriptor;
use miden_node_store::BlockStore;
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use crate::db::{ValidatorDbReader, ValidatorDbWriter};
use crate::{
    DataDirectory,
    GoldenOperatorKey,
    LOG_TARGET,
    PrivateRecordSealer,
    TransactionInputDecrypter,
    ValidatorSigner,
};

mod admin_service;
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
    /// gRPC server options for internal services (timeouts, connection caps).
    ///
    /// If the handler takes longer than this duration, the server cancels the call.
    pub grpc_options: GrpcOptions,

    /// The signer used to sign blocks.
    pub signer: ValidatorSigner,

    /// The decrypter for the shared transaction encryption key, used to unseal encrypted
    /// transaction inputs.
    pub decrypter: std::sync::Arc<dyn TransactionInputDecrypter>,

    /// The public Golden key used to seal private records.
    pub private_record_sealer: PrivateRecordSealer,

    /// The data directory for the validator component's database files.
    pub data_directory: DataDirectory,

    /// Handle to the shared validator database. Carrying the write handle makes the public API the
    /// database's single writer; reads reach the shared read handle through its `Deref`.
    pub db: ValidatorDbWriter,
}

/// Serves the private validator administration API on a network-isolated listener.
pub struct ValidatorAdminServer {
    /// Address of the private administration listener.
    pub address: SocketAddr,
    /// Golden key material used to issue this validator's decryption shares.
    pub operator_key: GoldenOperatorKey,
    /// Read handle to the shared validator database. The administration API only ever reads, so it
    /// holds a [`ValidatorDbReader`] and cannot mutate validator state.
    pub reader: ValidatorDbReader,
}

impl ValidatorAdminServer {
    /// Serves the private validator administration API.
    pub async fn serve(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let listener =
            TcpListener::bind(self.address).await.context("failed to bind admin address")?;
        self.serve_on(listener, shutdown).await
    }

    async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let endpoint =
            listener.local_addr().context("failed to read validator admin listen address")?;
        tracing::info!(
            target: LOG_TARGET,
            {
                service.name = "miden-validator-admin",
                validator.admin_listen = %endpoint,
            },
            "Validator admin server ready",
        );

        axum::serve(listener, admin_service::router(self.operator_key, self.reader))
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .context("failed to serve validator admin API")
    }
}

impl ValidatorServer {
    /// Serves the validator RPC API.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // The database pool is opened once by the caller and shared with the admin server, so this
        // takes the handle rather than opening its own connection.
        let db = self.db;

        // Initialize block store.
        let block_store = BlockStore::load(self.data_directory.block_store_dir())
            .context("failed to load block store")?;

        // Load initial metrics from the database for the in-memory counters.
        let metrics = db.load_initial_metrics().await.context("failed to load initial metrics")?;

        let listener = TcpListener::bind(self.address)
            .await
            .context("failed to bind to block producer address")?;

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(validator_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        let service = ValidatorService::new(
            self.signer,
            db,
            self.decrypter,
            self.private_record_sealer,
            block_store,
            metrics,
        )
        .await
        .context("failed to initialize validator server")?;
        let endpoint = listener.local_addr().context("failed to read validator listen address")?;
        tracing::info!(
            target: LOG_TARGET,
            {
                service.name = "miden-validator",
                service.version = env!("CARGO_PKG_VERSION"),
                validator.listen = %endpoint,
                block.number = metrics.chain_tip,
            },
            "Validator ready",
        );

        // Build the gRPC server with the API service and trace layer.
        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .timeout(self.grpc_options.request_timeout)
            .add_service(validator_api::service(service))
            .add_service(reflection_service)
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                shutdown.cancelled_owned(),
            )
            .await
            .context("failed to serve validator API")
    }
}
